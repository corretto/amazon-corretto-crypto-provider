#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from util.env_util import EnvUtil

# Used when AWS CDK defines AWS resources.
AWS_ACCOUNT = EnvUtil.get("CDK_DEPLOY_ACCOUNT", "838297025124")
AWS_REGION = EnvUtil.get("CDK_DEPLOY_REGION", "us-west-2")

# Used when AWS CDK defines ECR repos.
LINUX_X86_ECR_REPO = EnvUtil.get("ECR_LINUX_X86_REPO_NAME", "accp-docker-images-linux-x86")

# Used when AWS CodeBuild needs to create web_hooks.
GITHUB_REPO_OWNER = EnvUtil.get("GITHUB_REPO_OWNER", "corretto")
GITHUB_REPO_NAME = EnvUtil.get("GITHUB_REPO_NAME", "amazon-corretto-crypto-provider")
GITHUB_SOURCE_VERSION = EnvUtil.get("GITHUB_SOURCE_VERSION", "develop")
