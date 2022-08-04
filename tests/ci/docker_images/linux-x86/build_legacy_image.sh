#!/bin/bash -ex
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

if [ -n "$1" ]; then
  docker_name="$1"
else
  docker_name='ubuntu-10.04_gcc-4.1x_corretto'
fi

mkdir -p dependencies
cd dependencies

# The wget version that comes with this docker image is too old to
# access modern website sources, so we predownload the dependencies
# outside of the image and pull it in the container.
wget -O cmake-3.9.6.tar.gz https://cmake.org/files/v3.9/cmake-3.9.6.tar.gz
wget -O amazon-corretto-11-x64-linux-jdk.deb https://corretto.aws/downloads/latest/amazon-corretto-11-x64-linux-jdk.deb
wget -O lcov-1.14-1.noarch.rpm http://downloads.sourceforge.net/ltp/lcov-1.14-1.noarch.rpm
cd ..
docker build -t ubuntu-10.04:gcc-4.1x_corretto -f ${docker_name}/Dockerfile ../../../../

# Remove downloaded dependencies.
sudo rm -rf dependencies
cd ..
