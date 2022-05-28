# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

FROM ubuntu-20.04:accp_base-arm

SHELL ["/bin/bash", "-c"]

# Change default compiler to gcc7.
RUN apt-get install -y gcc-7 g++-7
RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-7 70 \
                        --slave /usr/bin/g++ g++ /usr/bin/g++-7 \
                        --slave /usr/bin/gcov gcov /usr/bin/gcov-7

# install corretto JDK for those we test upon.
RUN apt-get install -y java-1.8.0-amazon-corretto-jdk
RUN apt-get install -y java-11-amazon-corretto-jdk
RUN apt-get install -y java-17-amazon-corretto-jdk

RUN mkdir /accp
COPY . /accp
WORKDIR /accp

# run the gradlew script just to install gradle in the image
RUN ./gradlew --no-daemon generateEclipseClasspath

# Set default java to corretto 11.
ENV JAVA_HOME=/usr/lib/jvm/java-11-amazon-corretto/
