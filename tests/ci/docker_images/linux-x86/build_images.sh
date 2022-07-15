#!/bin/bash -ex
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

########################################
# Build images from ACCP GitHub repo #
########################################

# Log Docker hub limit https://docs.docker.com/docker-hub/download-rate-limit/#how-can-i-check-my-current-rate
TOKEN=$(curl "https://auth.docker.io/token?service=registry.docker.io&scope=repository:ratelimitpreview/test:pull" | jq -r .token)
curl --head -H "Authorization: Bearer $TOKEN" https://registry-1.docker.io/v2/ratelimitpreview/test/manifests/latest

docker build -t ubuntu-20.04:accp_base ubuntu-20.04_accp_base
# `../../../../` passes in the Dockerfile in this folder but uses the root directory for the context so it has access to 
# our project's gradle script.
docker build -t ubuntu-20.04:gcc-7x_corretto -f ubuntu-20.04_gcc-7x_corretto/Dockerfile ../../../../
docker build -t amazonlinux-2:accp_base amazonlinux-2_accp_base
docker build -t amazonlinux-2:gcc-7x_corretto -f amazonlinux-2_gcc-7x_corretto/Dockerfile ../../../../
