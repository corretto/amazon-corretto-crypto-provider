FROM public.ecr.aws/docker/library/centos:centos6

RUN mkdir -p /var/cache/yum/x86_64/6/base
RUN mkdir -p /var/cache/yum/x86_64/6/extras
RUN mkdir -p /var/cache/yum/x86_64/6/updates
RUN mkdir -p /var/cache/yum/x86_64/6/centos-sclo-rh
RUN mkdir -p /var/cache/yum/x86_64/6/centos-sclo-sclo

RUN echo "https://vault.centos.org/6.10/os/x86_64/" > /var/cache/yum/x86_64/6/base/mirrorlist.txt
RUN echo "http://vault.centos.org/6.10/extras/x86_64/" > /var/cache/yum/x86_64/6/extras/mirrorlist.txt
RUN echo "http://vault.centos.org/6.10/updates/x86_64/" > /var/cache/yum/x86_64/6/updates/mirrorlist.txt
RUN echo "http://vault.centos.org/6.10/sclo/x86_64/rh" > /var/cache/yum/x86_64/6/centos-sclo-rh/mirrorlist.txt
RUN echo "http://vault.centos.org/6.10/sclo/x86_64/sclo" > /var/cache/yum/x86_64/6/centos-sclo-sclo/mirrorlist.txt

RUN yum -y update
RUN yum -y install centos-release-scl
RUN yum -y install devtoolset-7-gcc-c++ gsl wget perl patch

RUN curl -L -O https://github.com/Kitware/CMake/releases/download/v3.14.3/cmake-3.14.3.tar.gz
RUN tar xzf cmake-3.14.3.tar.gz
RUN (cd cmake-3.14.3 && scl enable devtoolset-7 ./bootstrap && scl enable devtoolset-7 gmake && gmake install)

RUN ln -s /usr/local/bin/cmake /usr/local/bin/cmake3

RUN curl -L -O https://downloads.sourceforge.net/ltp/lcov-1.14-1.noarch.rpm

RUN curl -L -O https://d3pxv6yz143wms.cloudfront.net/11.0.3.7.1/java-11-amazon-corretto-devel-11.0.3.7-1.x86_64.rpm

RUN rpm -i java-11-amazon-corretto-devel-11.0.3.7-1.x86_64.rpm
