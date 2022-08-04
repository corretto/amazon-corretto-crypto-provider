#!/bin/bash -ex
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

source ./common.sh

if [ -z ${1+x} ]; then
  ECS_REPO="838297025124.dkr.ecr.us-west-2.amazonaws.com/accp-docker-images-linux"
else
  ECS_REPO=$1
fi

echo "Uploading docker images to ${ECS_REPO}."

$(aws ecr get-login --no-include-email)

# Tag images with date to help find old images, CodeBuild uses the latest tag and gets updated automatically
tag_and_push_img 'ubuntu-20.04:gcc-7x_corretto-arm' "${ECS_REPO}:ubuntu-20.04_gcc-7x_corretto_arm"
tag_and_push_img 'amazonlinux-2:gcc-7x_corretto-arm' "${ECS_REPO}:amazonlinux-2_gcc-7x_corretto_arm"
