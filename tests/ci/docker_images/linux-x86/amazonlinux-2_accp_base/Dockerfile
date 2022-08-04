# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

FROM amazonlinux:2

SHELL ["/bin/bash", "-c"]

RUN set -ex && \
    yum -y update && yum install -y \
    cmake \
    cmake3 \
    make \
    ninja-build \
    perl \
    golang \
    which \
    git \
    ca-certificates \
    wget \
    yum clean packages && \
    yum clean metadata && \
    yum clean all && \
    rm -rf /tmp/* && \
    rm -rf /var/cache/yum

# Get lcov from source because AL2 doesn't have support for installing directly.
RUN wget http://downloads.sourceforge.net/ltp/lcov-1.14-1.noarch.rpm && \
    yum localinstall -y lcov-1.14-1.noarch.rpm

ENV GO111MODULE=on
