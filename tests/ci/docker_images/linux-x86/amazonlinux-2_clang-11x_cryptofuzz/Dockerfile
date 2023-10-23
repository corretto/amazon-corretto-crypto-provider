# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

FROM amazonlinux-2:clang-11x

SHELL ["/bin/bash", "-c"]

RUN set -ex && \
    yum -y update && yum install -y \
    libtool \
    unzip \
    llvm \
    llvm-devel \
    lld \
    compiler-rt \
    perl-core \
    java-17-amazon-corretto \
    java-17-amazon-corretto-devel && \
    yum clean packages && \
    yum clean metadata && \
    yum clean all && \
    rm -rf /tmp/* && \
    rm -rf /var/cache/yum

ENV JAVA_HOME=/usr/lib/jvm/java-17-amazon-corretto.x86_64

ENV FUZZ_ROOT=${DEPENDENCIES_DIR}
ENV MODULE_ROOT="${FUZZ_ROOT}/modules"

# Cryptofuzz wants cmake3 so we make it AL2's default cmake via symlink
RUN ln -s `which cmake3` /usr/local/bin/cmake

COPY tests/ci/docker_images/dependencies/build_cryptofuzz_modules.sh \
    tests/ci/docker_images/dependencies/cryptofuzz_data.zip \
    $FUZZ_ROOT/
RUN set -ex && cd $FUZZ_ROOT && "./build_cryptofuzz_modules.sh"