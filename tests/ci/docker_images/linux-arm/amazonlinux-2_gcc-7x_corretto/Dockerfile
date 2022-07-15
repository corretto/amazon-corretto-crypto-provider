# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

FROM amazonlinux-2:accp_base-arm

SHELL ["/bin/bash", "-c"]

RUN amazon-linux-extras enable corretto8

# gcc 7.3.1 is the latest version versions `yum --showduplicates list gcc`
# JRE and JDK tools are separate in Corretto 17.
RUN set -ex && \
    yum -y update && yum install -y \
    gcc \
    gcc-c++ \
    java-1.8.0-amazon-corretto-devel \
    java-11-amazon-corretto \
    java-17-amazon-corretto \
    java-17-amazon-corretto-devel && \
    yum clean packages && \
    yum clean metadata && \
    yum clean all && \
    rm -rf /tmp/* && \
    rm -rf /var/cache/yum

RUN mkdir /accp
COPY . /accp
WORKDIR /accp

# run the gradlew script just to install gradle in the image
RUN ./gradlew --no-daemon generateEclipseClasspath

ENV CC=gcc
ENV CXX=g++
ENV JAVA_HOME=/usr/lib/jvm/java-11-amazon-corretto.aarch64
