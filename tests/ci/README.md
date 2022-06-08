# CI for ACCP
We use prebuilt docker images for all of our builds for speed and consistency.

## Setup
 To setup the images for local testing or testing in your own AWS account see
the platform specific `README` in docker_images/*.

Once you have the docker images uploaded to AWS Elastic Container Registry you
can setup the AWS CodeBuild projects that use the custom image with the
appropriate buildspec files in codebuild/*.

## Local testing
The best way to test ACCP locally is to use the same Docker containers AWS
CodeBuild uses.
1. Install Docker
2. Navigate to your ACCP project directory
3. Build the docker image you want to test
4. Run the docker image
   *   Use `-v` to pass a volume from the host to the container, `pwd`:`pwd`
       mounts the same path on the host to the container. This ensures the
       container will build and test your exact working state.
   *  Use `-w` to change to that directory inside the container after launching
      it
5. Run the build

For example testing x86-64 Ubuntu 20.04 with gcc7 as default and corretto 8, 11, and 17 available:
```
$ cd $ACCP_PROJECT_ROOT
$ docker build -t ubuntu-20.04:gcc-7x_corretto tests/ci/docker_images/linux-x86/ubuntu-20.04_gcc-7x_corretto/
$ docker run -v `pwd`:`pwd` -w `pwd` -it ubuntu-20.04:gcc-7x_corretto
$ ./tests/ci/run_accp_basic_tests.sh
```

## Test locations
### Unit tests
Runs tests for:
* release
* test_integration

CI Tool|C Compiler|Java Compiler|CPU platform|OS|Dimensions
------------ | -------------| -------------| -------------|-------------|-------------
CodeBuild|gcc 7|corretto 8|x86-64|Ubuntu 20.04|FIPS/non-FIPS
CodeBuild|gcc 7|corretto 11|x86-64|Ubuntu 20.04|FIPS/non-FIPS
CodeBuild|gcc 7|corretto 17|x86-64|Ubuntu 20.04|FIPS/non-FIPS
CodeBuild|gcc 7|corretto 8|aarch|Ubuntu 20.04|FIPS/non-FIPS
CodeBuild|gcc 7|corretto 11|aarch|Ubuntu 20.04|FIPS/non-FIPS
CodeBuild|gcc 7|corretto 17|aarch|Ubuntu 20.04|FIPS/non-FIPS
~~GitHub Workflow~~|~~AppleClang 13.0.0~~|~~corretto 8~~|~~x86-64~~|~~macOS 11~~|~~FIPS/non-FIPS~~
~~GitHub Workflow~~|~~AppleClang 13.0.0~~|~~corretto 11~~|~~x86-64~~|~~macOS 11~~|~~FIPS/non-FIPS~~
~~GitHub Workflow~~|~~AppleClang 13.0.0~~|~~corretto 17~~|~~x86-64~~|~~macOS 11~~|~~FIPS/non-FIPS~~

(macOS CI dimension is currently disabled, go to the Actions tab in the main repo to enable it when its ready.)


### Dieharder & Overkill tests
Runs tests for:
* test_extra_checks
* test_integration_extra_checks
* dieharder_threads

CI Tool|C Compiler|Java Compiler|CPU platform|OS|Dimensions
------------ | -------------| -------------| -------------|-------------|-------------
CodeBuild|gcc 7|corretto 11|x86-64|Ubuntu 20.04|both FIPS/non-FIPS
CodeBuild|gcc 7|corretto 11|aarch|Ubuntu 20.04|both FIPS/non-FIPS, no dieharder
