#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from aws_cdk import core

from cdk.accp_github_ci_stack import ACCPGitHubCIStack
from cdk.linux_docker_image_batch_build_stack import LinuxDockerImageBatchBuildStack
from cdk.ecr_stack import EcrStack
from util.metadata import AWS_ACCOUNT, AWS_REGION, LINUX_X86_ECR_REPO

# Initialize app.
app = core.App()

# Initialize env.
env = core.Environment(account=AWS_ACCOUNT, region=AWS_REGION)

# Define AWS ECR stacks.
# ECR holds the docker images, which are pre-built to accelerate the code builds/tests of git pull requests.
EcrStack(app, "accp-ecr-linux-x86", LINUX_X86_ECR_REPO, env=env)

# Define CodeBuild Batch job for building Docker images.
LinuxDockerImageBatchBuildStack(app, "accp-docker-image-build-linux", env=env)

# Define CodeBuild Batch job for testing code.
x86_build_spec_file = "./cdk/codebuild/pr_integration_linux_x86_omnibus.yaml"
ACCPGitHubCIStack(app, "accp-ci-pr-integration-linux-x86", LINUX_X86_ECR_REPO, x86_build_spec_file, env=env)
extra_build_spec_file = "./cdk/codebuild/dieharder_overkill_omnibus.yaml"
ACCPGitHubCIStack(app, "accp-ci-overkill-dieharder", LINUX_X86_ECR_REPO, extra_build_spec_file, env=env)

app.synth()
