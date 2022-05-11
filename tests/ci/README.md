# CI for ACCP
We use prebuilt docker images for all of our builds for speed and consistency.

## Setup
 To setup the images for local testing or testing in your own AWS account see
the platform specific `README` in docker_images/*.

Once you have the docker images uploaded to AWS Elastic Container Registry you
can setup the AWS CodeBuild projects that use the custom image with the
appropriate buildspec files in codebuild/*.

## Local testing
The best way to test AWS-LC locally is to use the same Docker containers AWS
CodeBuild uses.
1. Install Docker
2. Navigate to your AWS-LC project directory
3. Build the docker image you want to test
4. Run the docker image
   *   Use `-v` to pass a volume from the host to the container, `pwd`:`pwd`
       mounts the same path on the host to the container. This ensures the
       container will build and test your exact working state.
   *  Use `-w` to change to that directory inside the container after launching
      it
5. Run the build

For example testing x86-64 Ubuntu 20.04 clang 9x:
```
$ cd $AWS_LC_PROJECT_ROOT
$ docker build -t ubuntu-20.04:clang-9x tests/ci/docker_images/linux-x86/ubuntu-20.04_clang-9x/
$ docker run -v `pwd`:`pwd` -w `pwd` -it ubuntu-20.04:clang-9x
$ ./tests/ci/run_posix_tests.sh
```

## Test locations
### Unit tests
Runs all tests for:
* Debug
* Release
* Small
* No assembly
* Shared libs

CI Tool|Compiler|CPU platform|OS
------------ | -------------| -------------|-------------
CodeBuild|gcc 4.8.5|x86|Centos 7
CodeBuild|gcc 4.8.5|x86-64|Centos 7
CodeBuild|gcc 5.4.0|x86|Ubuntu 16.04
CodeBuild|gcc 7.3.1|x86-64|AL2
CodeBuild|gcc 7.3.1|aarch64|AL2
CodeBuild|gcc 7.5.0|x86-64|Ubuntu 18.04
CodeBuild|gcc 7.5.0|x86-64|Ubuntu 20.04
CodeBuild|gcc 7.5.0|aarch64|Ubuntu 20.04
CodeBuild|gcc 8.4.0|x86-64|Ubuntu 20.04
CodeBuild|gcc 8.4.0|aarch64|Ubuntu 20.04
CodeBuild|clang 7.0.1|x86-64|AL2
CodeBuild|clang 7.0.1|aarch64|AL2
CodeBuild|clang 6.0.0|x86-64|Ubuntu 18.04
CodeBuild|clang 9.0.1|x86-64|Fedora 31
CodeBuild|clang 7.0.1|x86-64|Ubuntu 20.04
CodeBuild|clang 7.0.1|aarch64|Ubuntu 20.04
CodeBuild|clang 8.0.1|x86-64|Ubuntu 20.04
CodeBuild|clang 8.0.1|aarch64|Ubuntu 20.04
CodeBuild|clang 9.0.1|x86-64|Ubuntu 20.04
CodeBuild|clang 9.0.1|aarch64|Ubuntu 20.04
CodeBuild|clang 10.0.0|x86-64|Ubuntu 20.04
CodeBuild|clang 10.0.0|aarch64|Ubuntu 20.04
CodeBuild|Visual Studio 2015|x86-64|Windows Server 10
GitHub Workflow|AppleClang 13.0.0|x86-64|macOS 11

### Sanitizer tests
Runs all tests with:
* Address sanitizer
* Memory sanitizer
* Control flow integrity
* Thread sanitizer
* Undefined behavior sanitizer

CI Tool|Compiler|CPU platform|OS
------------ | -------------| -------------|-------------
CodeBuild|clang 9.0.1|x86-64|Ubuntu 20.04
CodeBuild|clang 9.0.1|aarch64|ubuntu 20.04

### Valgrind tests

The following Valgrind tests are run for a subset of targets in `utils/all_tests.json` using the debug build of AWS-LC:

CI Tool|Compiler|CPU platform|OS| memcheck 
------------ | -------------| -------------|-------------|-------------
CodeBuild|gcc 7.3.1|x86-64|AL2 | X

### Fuzz tests
All Fuzz tests under /fuzz are run in CodeBuild for an hour total.

CI Tool|Compiler|CPU platform|OS|Flags
------------|-------------|-------------|-------------|-------------
CodeBuild|clang 10.0.0|x86-64|Ubuntu 20.04|ASAN=1
CodeBuild|clang 10.0.0|aarch64|ubuntu 20.04|ASAN=1

To add a new fuzz test create a new executable follow [libFuzzer's](https://llvm.org/docs/LibFuzzer.html) documentation
and existing tests. Generate a seed corpus and check it into a folder with the same name as the executable. The CI will
pull in any files from the seed folder and merge it into the growing corpus in EFS.


### Cryptofuzz
Each change is built and tested with [Cryptofuzz](https://github.com/guidovranken/cryptofuzz) for an hour. A seed corpus
is included in tests/docker_images/cryptofuzz_data.zip. As new inputs are found they are saved in a shared corpus across
runs in AWS EFS. Cryptofuzz is built with 3 modules:
* AWS-LC
* Botan
* Crypto++

CI Tool|Compiler|CPU platform|OS|Flags
------------|-------------|-------------|-------------|-------------
CodeBuild|clang 10.0.0|x86-64|Ubuntu 20.04|ASAN=1