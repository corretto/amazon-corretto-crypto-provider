# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

FROM centos:7

SHELL ["/bin/bash", "-c"]

# This docker image is to test the oldest gcc version we can find
# on an OS that works with >= JDK10.
#
# We manually install go 1.14.10 because of the version of git
# for CentOS 7 is too old to support the `--unshallow` option
# https://github.com/golang/go/issues/38373
RUN set -ex && \
    yum -y update && \
    yum --enablerepo=extras install epel-release -y && \
    yum -y install \
    gcc \
    libgcc.i686 \
    glibc-devel.x86_64 \
    glibc-devel.i686 \
    gcc-c++ \
    libstdc++-devel.x86_64 \
    libstdc++-devel.i686 \
    cmake \
    cmake3 \
    make \
    ninja-build \
    perl \
    wget \
    cd /tmp && \
    wget https://golang.org/dl/go1.14.10.linux-amd64.tar.gz && \
    tar -xvf go1.14.10.linux-amd64.tar.gz && \
    mv go /usr/local && \
    yum clean packages && \
    yum clean metadata && \
    yum clean all && \
    rm -rf /tmp/* && \
    rm -rf /var/cache/yum

# Install a Java version to build with ACCP & gcc 4.8.5.
RUN rpm --import https://yum.corretto.aws/corretto.key && \
    curl -L -o /etc/yum.repos.d/corretto.repo https://yum.corretto.aws/corretto.repo && \
    yum install -y java-11-amazon-corretto-devel

ENV CC=gcc
ENV CXX=g++
ENV GOROOT=/usr/local/go
ENV PATH="$GOROOT/bin:$PATH"
ENV JAVA_HOME=/usr/lib/jvm/java-11-amazon-corretto

RUN mkdir /accp
COPY . /accp
WORKDIR /accp

# run the gradlew script just to install gradle in the image
RUN ./gradlew --no-daemon generateEclipseClasspath
