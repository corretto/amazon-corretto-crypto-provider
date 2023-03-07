#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from util.env_util import EnvUtil

# Used when AWS CDK defines AWS resources.
AWS_ACCOUNT = EnvUtil.get("CDK_DEPLOY_ACCOUNT", "838297025124")
AWS_REGION = EnvUtil.get("CDK_DEPLOY_REGION", "us-west-2")

# Used when AWS CDK defines ECR repos.
LINUX_ECR_REPO = EnvUtil.get("ECR_LINUX_REPO_NAME", "accp-docker-images-linux")
WINDOWS_X86_ECR_REPO = EnvUtil.get("ECR_WINDOWS_X86_REPO_NAME", "accp-docker-images-windows-x86")

# Used when AWS CodeBuild needs to create web_hooks.
GITHUB_REPO_OWNER = EnvUtil.get("GITHUB_REPO_OWNER", "corretto")
GITHUB_REPO_NAME = EnvUtil.get("GITHUB_REPO_NAME", "amazon-corretto-crypto-provider")
GITHUB_SOURCE_VERSION = EnvUtil.get("GITHUB_SOURCE_VERSION", "main")
GITHUB_BRANCH_EXCLUDE_CI = EnvUtil.get("GITHUB_BRANCH_EXCLUDE_CI", "v1")

# Used when AWS CDK defines resources for Windows docker image build.
S3_BUCKET_NAME = EnvUtil.get("S3_FOR_WIN_DOCKER_IMG_BUILD", "accp-windows-docker-image-build")
WIN_EC2_TAG_KEY = EnvUtil.get("WIN_EC2_TAG_KEY", "accp")
WIN_EC2_TAG_VALUE = EnvUtil.get("WIN_EC2_TAG_VALUE", "accp-windows-docker-image-build")
SSM_DOCUMENT_NAME = EnvUtil.get("WIN_DOCKER_BUILD_SSM_DOCUMENT", "windows-ssm-document")
