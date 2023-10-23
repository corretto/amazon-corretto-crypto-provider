# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

FROM ubuntu:10.04

CMD ["/bin/bash"]

# The following hack is to avoid a problem where glibc update fails b/c kernel revision is >255
# https://bugs.launchpad.net/ubuntu/+source/glibc/+bug/1962225
RUN mv /bin/uname /bin/uname.orig
RUN printf '#!/bin/bash\n\nif [[ "$1" == "-r" ]] ;then\n echo '4.9.250'\n exit\nelse\n uname.orig "$@"\nfi' > /bin/uname
RUN chmod 755 /bin/uname

RUN sed -i -re 's/([a-z]{2}\.)?archive.ubuntu.com|security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list && \
    apt-get update && \
    apt-get -y --no-install-recommends install \
    gcc-4.1 \
    g++-4.1 \
    make \
    perl \
    python-pip \
    java-common \
    alien

RUN update-alternatives --install /usr/bin/cc gcc /usr/bin/gcc-4.1 70 --slave /usr/bin/c++ g++ /usr/bin/g++-4.1 --slave /usr/bin/gcov gcov /usr/bin/gcov-4.1

ENV CC=gcc-4.1
ENV CXX=g++-4.1

# Pull lcov as an external source since the wget version
# on this image is too old to access the lcov source.
COPY tests/ci/docker_images/linux-x86/dependencies/lcov-1.14-1.noarch.rpm /tmp/lcov-1.14-1.noarch.rpm
RUN cd /tmp && \
    alien lcov-1.14-1.noarch.rpm && \
    dpkg --install lcov_1.14-2_all.deb

# Pull gcovr as an external pip package due to obsolete wget.
COPY tests/ci/docker_images/linux-x86/dependencies/gcovr-2.0.tar.gz /tmp/gcovr-2.0.tar.gz
RUN cd /tmp && \
    pip install /tmp/gcovr-2.0.tar.gz

# Pull cmake as an external source since the wget version
# on this image is too old to access the cmake repo.
COPY tests/ci/docker_images/linux-x86/dependencies/cmake-3.9.6.tar.gz /tmp/cmake-3.9.6.tar.gz
RUN cd /tmp && \
    tar -xvf cmake-3.9.6.tar.gz && \
    cd cmake-3.9.6 && \
    ./configure && make && make install

# Pull Amazon corretto as an external source and install.
COPY tests/ci/docker_images/linux-x86/dependencies/amazon-corretto-11-x64-linux-jdk.deb /tmp/amazon-corretto-11-x64-linux-jdk.deb
RUN cd /tmp && \
    dpkg --install amazon-corretto-11-x64-linux-jdk.deb

RUN mkdir /accp
COPY . /accp
WORKDIR /accp

# run the gradlew script just to install gradle in the image
RUN ./gradlew --no-daemon generateEclipseClasspath

ENV JAVA_HOME=/usr/lib/jvm/java-11-amazon-corretto
ENV PATH=$JAVA_HOME/bin:/usr/local/bin:$PATH
