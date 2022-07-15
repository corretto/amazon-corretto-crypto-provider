# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

docker build -t accp/windows_base:2019 .\windows_base
docker build -t vs2015_corretto .\vs2015_corretto
docker build -t vs2017_corretto .\vs2017_corretto
