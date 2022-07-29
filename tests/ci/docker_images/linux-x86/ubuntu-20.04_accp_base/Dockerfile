# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

FROM ubuntu:20.04

SHELL ["/bin/bash", "-c"]

ENV DEBIAN_FRONTEND=noninteractive
ENV GO_TAG=go1.18.3

# required dependencies for building/testing
RUN apt-get update
RUN apt-get install -y curl
RUN apt-get install -y gnupg
RUN apt-get install -y build-essential
RUN apt-get install -y cmake
RUN apt-get install -y dieharder
RUN apt-get install -y lcov
RUN apt-get install -y wget
RUN apt-get install -y python3-pip
RUN pip3 install gcovr

# developement niceties
RUN apt-get install -y ninja-build
RUN apt-get install -y git

# fetch corretto repo
RUN curl -s https://apt.corretto.aws/corretto.key | apt-key add -
RUN echo 'deb https://apt.corretto.aws stable main' | tee /etc/apt/sources.list.d/corretto.list
RUN apt-get update

# AWS-LC FIPS requires golang.
RUN cd /tmp && \
    wget https://dl.google.com/go/$GO_TAG.linux-amd64.tar.gz && \
    tar -xvf $GO_TAG.linux-amd64.tar.gz && \
    mv go /usr/local && \
    rm -rf /tmp/*

ENV GOROOT=/usr/local/go
ENV GO111MODULE=on
ENV PATH="$GOROOT/bin:$PATH"
