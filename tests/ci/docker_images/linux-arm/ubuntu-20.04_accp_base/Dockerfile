# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

FROM arm64v8/ubuntu:20.04

SHELL ["/bin/bash", "-c"]

ENV DEBIAN_FRONTEND=noninteractive

# required dependencies for building/testing
RUN apt-get update
RUN apt-get install -y curl
RUN apt-get install -y gnupg
RUN apt-get install -y build-essential
RUN apt-get install -y cmake
RUN apt-get install -y dieharder
RUN apt-get install -y lcov

# developement niceties
RUN apt-get install -y ninja-build
RUN apt-get install -y git

# fetch corretto repo
RUN curl -s https://apt.corretto.aws/corretto.key | apt-key add -
RUN echo 'deb https://apt.corretto.aws stable main' | tee /etc/apt/sources.list.d/corretto.list
RUN apt-get update
