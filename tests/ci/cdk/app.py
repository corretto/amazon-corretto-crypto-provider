#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from aws_cdk import core

from cdk.accp_github_ci_stack import ACCPGitHubCIStack
from cdk.linux_docker_image_batch_build_stack import LinuxDockerImageBatchBuildStack
from cdk.windows_docker_image_build_stack import WindowsDockerImageBuildStack
from cdk.ecr_stack import EcrStack
from util.metadata import AWS_ACCOUNT, AWS_REGION, LINUX_ECR_REPO, WINDOWS_X86_ECR_REPO

# Initialize app.
app = core.App()

# Initialize env.
env = core.Environment(account=AWS_ACCOUNT, region=AWS_REGION)

# Define AWS ECR stacks.
# ECR holds the docker images, which are pre-built to accelerate the code builds/tests of git pull requests.
EcrStack(app, "accp-ecr-linux-all", LINUX_ECR_REPO, env=env)

# Renable the code below when ACCP adds support for Windows.
# Issue: https://github.com/corretto/amazon-corretto-crypto-provider/issues/48
EcrStack(app, "accp-ecr-windows-x86", WINDOWS_X86_ECR_REPO, env=env)

# Define CodeBuild Batch job for building Docker images.
LinuxDockerImageBatchBuildStack(app, "accp-docker-image-build-linux", env=env)

# Renable the code below when ACCP adds support for Windows.
# Issue: https://github.com/corretto/amazon-corretto-crypto-provider/issues/48
#
# AWS CodeBuild cannot build Windows Docker images because DIND (Docker In Docker) is not supported on Windows.
# Windows Docker images are created by running commands in Windows EC2 instance.
# WindowsDockerImageBuildStack(app, "accp-docker-image-build-windows", env=env)

# Define CodeBuild Batch job for testing code.
x86_build_spec_file = "./cdk/codebuild/pr_integration_linux_x86_omnibus.yaml"
ACCPGitHubCIStack(app, "accp-ci-pr-integration-linux-x86", LINUX_ECR_REPO, x86_build_spec_file, env=env)
arm_build_spec_file = "./cdk/codebuild/pr_integration_linux_arm_omnibus.yaml"
ACCPGitHubCIStack(app, "accp-ci-pr-integration-linux-arm", LINUX_ECR_REPO, arm_build_spec_file, env=env)
extra_build_spec_file = "./cdk/codebuild/dieharder_overkill_omnibus.yaml"
ACCPGitHubCIStack(app, "accp-ci-overkill-dieharder", LINUX_ECR_REPO, extra_build_spec_file, env=env)

# Renable the code below when ACCP adds support for Windows.
# Issue: https://github.com/corretto/amazon-corretto-crypto-provider/issues/48
#
# win_x86_build_spec_file = "./cdk/codebuild/pr_integration_windows_x86_omnibus.yaml"
# ACCPGitHubCIStack(app, "accp-ci-pr-integration-windows-x86", WINDOWS_X86_ECR_REPO, win_x86_build_spec_file, env=env)

app.synth()
