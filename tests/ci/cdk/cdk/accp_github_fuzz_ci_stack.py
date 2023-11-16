# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC


from aws_cdk import core, aws_codebuild as codebuild, aws_iam as iam, aws_ec2 as ec2, aws_efs as efs
from util.ecr_util import ecr_arn
from util.iam_policies import code_build_batch_policy_in_json
from util.metadata import AWS_ACCOUNT, AWS_REGION, GITHUB_BRANCH_EXCLUDE_CI, GITHUB_REPO_OWNER, GITHUB_REPO_NAME
from util.yml_loader import YmlLoader

class ACCPGitHubFuzzCIStack(core.Stack):
    """Define a stack used to batch execute ACCP tests in GitHub."""

    def __init__(self,
                 scope: core.Construct,
                 id: str,
                 ecr_repo_name: str,
                 spec_file_path: str,
                 **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # Define CodeBuild resource.
        git_hub_source = codebuild.Source.git_hub(
            owner=GITHUB_REPO_OWNER,
            repo=GITHUB_REPO_NAME,
            webhook=True,
            fetch_submodules=True,
            webhook_filters=[
                codebuild.FilterGroup.in_event_of(
                    codebuild.EventAction.PULL_REQUEST_MERGED,
                    codebuild.EventAction.PULL_REQUEST_CREATED,
                    codebuild.EventAction.PULL_REQUEST_UPDATED,
                    codebuild.EventAction.PULL_REQUEST_REOPENED)
                .and_base_branch_is_not(GITHUB_BRANCH_EXCLUDE_CI)
            ],
            webhook_triggers_batch_build=True)

        # Define a IAM role for this stack.
        code_build_batch_policy = iam.PolicyDocument.from_json(
            code_build_batch_policy_in_json([id])
        )
        inline_policies = {"code_build_batch_policy": code_build_batch_policy}
        role = iam.Role(scope=self,
                        id="{}-role".format(id),
                        assumed_by=iam.ServicePrincipal("codebuild.amazonaws.com"),
                        inline_policies=inline_policies)

        # Create the VPC for EFS and CodeBuild
        public_subnet = ec2.SubnetConfiguration(name="PublicFuzzingSubnet", subnet_type=ec2.SubnetType.PUBLIC)
        private_subnet = ec2.SubnetConfiguration(name="PrivateFuzzingSubnet", subnet_type=ec2.SubnetType.PRIVATE)

        # Create a VPC with a single public and private subnet in a single AZ. This is to avoid the elastic IP limit
        # being used up by a bunch of idle NAT gateways
        fuzz_vpc = ec2.Vpc(
            scope=self,
            id="{}-FuzzingVPC".format(id),
            subnet_configuration=[public_subnet, private_subnet],
            max_azs=1
        )
        build_security_group = ec2.SecurityGroup(
            scope=self,
            id="{}-FuzzingSecurityGroup".format(id),
            vpc=fuzz_vpc
        )

        build_security_group.add_ingress_rule(
            peer=build_security_group,
            connection=ec2.Port.all_traffic(),
            description="Allow all traffic inside security group"
        )

        efs_subnet_selection = ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE)

        # Create the EFS to store the corpus and logs. EFS allows new filesystems to burst to 100 MB/s for the first 2
        # TB of data read/written, after that the rate is limited based on the size of the filesystem. As of late
        # 2021 our corpus is less than one GB which results in EFS limiting all reads and writes to the minimum 1 MB/s.
        # To have the fuzzing be able to finish in a reasonable amount of time use the Provisioned capacity option.
        # For now this uses 100 MB/s which matches the performance used for 2021. Looking at EFS metrics in late 2021
        # during fuzz runs EFS sees 4-22 MB/s of transfers thus 100 MB/s gives lots of buffer and allows ~4-5 fuzz runs
        # to start at the same time with no issue.
        # https://docs.aws.amazon.com/efs/latest/ug/performance.html
        fuzz_filesystem = efs.FileSystem(
            scope=self,
            id="{}-FuzzingEFS".format(id),
            file_system_name="ACCP-Fuzz-Corpus",
            enable_automatic_backups=True,
            encrypted=True,
            security_group=build_security_group,
            vpc=fuzz_vpc,
            vpc_subnets=efs_subnet_selection,
            performance_mode=efs.PerformanceMode.GENERAL_PURPOSE,
            throughput_mode=efs.ThroughputMode.PROVISIONED,
            provisioned_throughput_per_second=core.Size.mebibytes(100),
        )

        placeholder_map = {"ECR_REPO_PLACEHOLDER": ecr_arn(ecr_repo_name)}
        build_spec_content = YmlLoader.load(spec_file_path, placeholder_map)

        # The EFS identifier needs to match tests/ci/common_fuzz.sh, CodeBuild defines an environment variable named
        # codebuild_$identifier.
        # https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codebuild-project-projectfilesystemlocation.html
        efs_location = codebuild.FileSystemLocation.efs(
            identifier="fuzzing_root",
            location="%s.efs.%s.amazonaws.com:/" % (fuzz_filesystem.file_system_id, AWS_REGION),
            mount_point="/efs_fuzzing_root")
        # Define CodeBuild.
        fuzz_codebuild = codebuild.Project(
            scope=self,
            id="FuzzingCodeBuild",
            project_name=id,
            source=git_hub_source,
            role=role,
            timeout=core.Duration.minutes(120),
            environment=codebuild.BuildEnvironment(compute_type=codebuild.ComputeType.LARGE,
                                                   privileged=True,
                                                   build_image=codebuild.LinuxBuildImage.STANDARD_4_0),
            build_spec=codebuild.BuildSpec.from_object(build_spec_content),
            vpc=fuzz_vpc,
            security_groups=[build_security_group],
            file_system_locations=[efs_location]
        )
        fuzz_codebuild.enable_batch_builds()
