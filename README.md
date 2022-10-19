# Amazon Corretto Crypto Provider
The Amazon Corretto Crypto Provider (ACCP) is a collection of high-performance cryptographic implementations exposed via the standard [JCA/JCE](https://docs.oracle.com/en/java/javase/11/security/java-cryptography-architecture-jca-reference-guide.html) interfaces.
This means that it can be used as a drop in replacement for many different Java applications.
(Differences from the default OpenJDK implementations are [documented here](./DIFFERENCES.md).)
As of 2.0.0, algorithms exposed by ACCP are primarily backed by [AWS-LC](https://github.com/awslabs/aws-lc)'s implementations.

[Security issue notifications](./CONTRIBUTING.md#security-issue-notifications)


## Build Status
Please be aware that both "Overkill" and "Dieharder" tests are known to be flakey.
Both of these tests are flakey because they include entropy generation tests
(specificaly, the [Dieharder tests](http://webhome.phy.duke.edu/~rgb/General/dieharder.php)).
Entropy tests are unavoidably flakey because there is always a possibility that a high-quality
random number generator will output data which looks non-random.
(For example, even a fair coin will come up heads ten times in a row about one in a thousand trials.)

| Build Name | master branch | develop branch |
| ---------- | ------------- | -------------- |
| x86        | ![Build Badge](https://codebuild.us-west-2.amazonaws.com/badges?uuid=eyJlbmNyeXB0ZWREYXRhIjoiRW4zZUhmeHlJbHRVQnNBZGZEbVJUa0pOK0J0MmtnNVB2dVZZSWhLbUtaNWYxNG96WWg4emN1SjJKL3VSUk9obFl0MnBtajBxejlVWDFiR3ppZGd3U1lrPSIsIml2UGFyYW1ldGVyU3BlYyI6IkFsUkpiMDRkRjZQb1U3Ly8iLCJtYXRlcmlhbFNldFNlcmlhbCI6MX0%3D&branch=master) | ![Build Badge](https://codebuild.us-west-2.amazonaws.com/badges?uuid=eyJlbmNyeXB0ZWREYXRhIjoiRW4zZUhmeHlJbHRVQnNBZGZEbVJUa0pOK0J0MmtnNVB2dVZZSWhLbUtaNWYxNG96WWg4emN1SjJKL3VSUk9obFl0MnBtajBxejlVWDFiR3ppZGd3U1lrPSIsIml2UGFyYW1ldGVyU3BlYyI6IkFsUkpiMDRkRjZQb1U3Ly8iLCJtYXRlcmlhbFNldFNlcmlhbCI6MX0%3D&branch=develop) |
| aarch64    | ![Build Badge](https://codebuild.us-west-2.amazonaws.com/badges?uuid=eyJlbmNyeXB0ZWREYXRhIjoiMEVNSXhZYmdEOWFrcE1HdE9nQmdwVlZFZXRYVnloc05TMXhoZ0tTVUQ1ZlMzeWRrZTArSUxUdzY2RVJRbUtXak5zU2ZCamJBS3JxUEFxZFJ2ZVNkcGVNPSIsIml2UGFyYW1ldGVyU3BlYyI6Ii80UEZpYWc2RjJZLzZDQ0wiLCJtYXRlcmlhbFNldFNlcmlhbCI6MX0%3D&branch=master) | ![Build Badge](https://codebuild.us-west-2.amazonaws.com/badges?uuid=eyJlbmNyeXB0ZWREYXRhIjoiMEVNSXhZYmdEOWFrcE1HdE9nQmdwVlZFZXRYVnloc05TMXhoZ0tTVUQ1ZlMzeWRrZTArSUxUdzY2RVJRbUtXak5zU2ZCamJBS3JxUEFxZFJ2ZVNkcGVNPSIsIml2UGFyYW1ldGVyU3BlYyI6Ii80UEZpYWc2RjJZLzZDQ0wiLCJtYXRlcmlhbFNldFNlcmlhbCI6MX0%3D&branch=develop) |
| Dieharder/Overkill Tests | ![Build Badge](https://codebuild.us-west-2.amazonaws.com/badges?uuid=eyJlbmNyeXB0ZWREYXRhIjoiRU14ZXM3ZkE4TGduVGV6dkxxWitxbkk3Ump2TnF3elkvYVRzcnkwQ3l4czl1OGRkc3NWblQ2Q0hxQkM2OWJ4VGdmL0x0Y01WYVVkWTdKYXNvbUpvS01VPSIsIml2UGFyYW1ldGVyU3BlYyI6Ilk3Y1NzbGNEZXZXY05CN2IiLCJtYXRlcmlhbFNldFNlcmlhbCI6MX0%3D&branch=master) | ![Build Badge](https://codebuild.us-west-2.amazonaws.com/badges?uuid=eyJlbmNyeXB0ZWREYXRhIjoiRU14ZXM3ZkE4TGduVGV6dkxxWitxbkk3Ump2TnF3elkvYVRzcnkwQ3l4czl1OGRkc3NWblQ2Q0hxQkM2OWJ4VGdmL0x0Y01WYVVkWTdKYXNvbUpvS01VPSIsIml2UGFyYW1ldGVyU3BlYyI6Ilk3Y1NzbGNEZXZXY05CN2IiLCJtYXRlcmlhbFNldFNlcmlhbCI6MX0%3D&branch=develop) |

## Supported Algorithms
MessageDigest algorithms:
* SHA-512
* SHA-384
* SHA-256
* SHA-1
* MD5

Mac algorithms:
* HmacSHA512
* HmacSHA384
* HmacSHA256
* HmacSHA1
* HmacMD5

Cipher algorithms:
* AES/GCM/NoPadding
* AES_128/GCM/NoPadding
* AES_256/GCM/NoPadding
* AES/KWP/NoPadding
* RSA/ECB/NoPadding
* RSA/ECB/PKCS1Padding
* RSA/ECB/OAEPPadding
* RSA/ECB/OAEPWithSHA-1AndMGF1Padding

Signature algorithms:
* SHA1withRSA
* SHA224withRSA
* SHA256withRSA
* SHA384withRSA
* SHA512withRSA
* NONEwithECDSA
* SHA1withECDSA
* SHA1withECDSAinP1363Format
* SHA224withECDSA
* SHA224withECDSAinP1363Format
* SHA256withECDSA
* SHA256withECDSAinP1363Format
* SHA384withECDSA
* SHA384withECDSAinP1363Format
* SHA512withECDSA
* SHA512withECDSAinP1363Format
* RSASSA-PSS

KeyPairGenerator algorithms:
* EC
* RSA

KeyAgreement:
* ECDH

SecureRandom algorithms:
* ACCP's SecureRandom uses AWS-LC's DRBG implementation, which is described [here](https://github.com/awslabs/aws-lc/blob/main/third_party/jitterentropy/README.md) and [here](https://github.com/awslabs/aws-lc/blob/725625435158150ef21e0a4dab6fa3aca1ef2d2c/crypto/fipsmodule/rand/rand.c#L36-L60).

KeyFactory algorithms:
* EC
* RSA
* ACCP's SecureRandom uses AWS-LC's DRBG implementation.

# Compatibility & Requirements
ACCP has the following requirements:
* JDK8 or newer (This includes both OracleJDK and [Amazon Corretto](https://aws.amazon.com/corretto/))
* 64-bit Linux or MacOs running on x86_64 (also known as x64 or AMD64)

If ACCP is used/installed on a system it does not support, it will disable itself and the JVM will behave as if ACCP weren't installed at all.

**Experimental** support for aarch64 (64-bit ARM) Linux systems was added in version 1.4.0.
(This is as an alternative to fully supported 64-bit Linux on x86_64.)
aarch64 support is still **experimental** and is not yet distributed via Maven.
If you want to experiment with ACCP on aarch64 platforms you will need to build it yourself as described later in this document.

# Using the provider
## Installation
Installing via Maven or Gradle is the easiest way to get ACCP and ensure you
will always have the most recent version. We strongly recommend you always pull
in the latest version for best performance and bug-fixes.

Whether you're using Maven, Gradle, or some other build system that also pulls
packages from Maven Central, it's important to specify `linux-x86_64` as the
classifier. You'll get an empty package otherwise. Note that ACCP will not be
available for MacOS on Maven Central until 2.0 is released.

Regardless of how you acquire ACCP (Maven, manual build, etc.) you will still need to follow the guidance in the [Configuration section](#configuration) to enable ACCP in your application.

### Maven
Add the following to your `pom.xml` or wherever you configure your Maven dependencies.
This will instruct it to use the most recent 1.x version of ACCP.
For more information, please see [VERSIONING.rst](https://github.com/corretto/amazon-corretto-crypto-provider/blob/develop/VERSIONING.rst).

The below snippet will pull in all versions of ACCP prior to the 2.0.0 release. Once 2.0.0 is released, we recommend that everyone switch to a specifier of `[2.0,3.0)`.

```xml
<dependency>
  <groupId>software.amazon.cryptools</groupId>
  <artifactId>AmazonCorrettoCryptoProvider</artifactId>
  <version>[1.0,2.0)</version>
  <classifier>linux-x86_64</classifier>
</dependency>
```

### Gradle
Add the following to your `build.gradle` file. If you already have a
`dependencies` block in your `build.gradle`, you can add the ACCP line to your
existing block.
This will instruct it to use the most recent 1.x version of ACCP.
For more information, please see [VERSIONING.rst](https://github.com/corretto/amazon-corretto-crypto-provider/blob/develop/VERSIONING.rst).

```groovy
dependencies {
    implementation 'software.amazon.cryptools:AmazonCorrettoCryptoProvider:1.+:linux-x86_64'
}
```

### Manual
Manual installation requires acquiring the provider and adding it to your classpath.
You can either download a prebuilt version of the provider or build it yourself.
Adding a jar to your classpath is highly application and build-system dependant and we cannot provide specific guidance.

#### Download from GitHub releases
The most recent version of our provider will always be on our official [releases](https://github.com/corretto/amazon-corretto-crypto-provider/releases) page.

#### Build it yourself
*Please be aware that if you build the provider yourself then it will NOT work with OracleJDK.
The OracleJDK requires that JCA providers be cryptographically signed by a trusted certificate.
The JARs we publish via Maven and our official [releases](https://github.com/corretto/amazon-corretto-crypto-provider/releases) are signed by our private key,
but yours will not be.*

Building this provider requires a 64 bit Linux or MacOS build system with the following prerequisites installed:
* OpenJDK 10 or newer
* [cmake](https://cmake.org/) 3.8 or newer
* C++ build chain
* [lcov](http://ltp.sourceforge.net/coverage/lcov.php) for coverage metrics
* [gcovr](https://gcovr.com/en/stable/) for reporting coverage metrics in CodeBuild
* [dieharder](http://webhome.phy.duke.edu/~rgb/General/dieharder.php) for entropy tests

1. Download the repository via `git clone --recurse-submodules`
2. Run `./gradlew release`
3. The resulting jar is in `build/lib`

##### FIPS builds
**FIPS builds are still experimental and are not yet ready for production use.**

By providing `-DFIPS=true` to `gradlew` you will cause the entire build to be for a "FIPS mode" build.
The only significant difference is that AWS-LC is built with `FIPS=1`.

When changing between FIPS and non-FIPS builds, be sure to do a full `clean` of your build environment.

##### All targets
* clean: Remove all artifacts except AWS-LC build artifacts
* deep_clean: Remove the entire `build/` directory including build artifacts from AWS-LC dependencies
* build: Build the library
* test: Run unit tests
* test_extra_checks: Run unit tests with extra (slow) cryptographic checks enabled
* test_integration: Run integration tests
* test_integration_extra_checks: Run integration tests with extra (slow) cryptographic checks enabled
* dieharder: Run entropy tests
* dieharder_threads: Run entropy threads specifically checking for leaking state across threads (very slow)
* dieharder_all: Run all dieharder checks (both dieharder and dieharder_threads)
* coverage: Run target `test` and collect both Java and C++ coverage metrics (saved in `build/reports`)
* release: **Default target** depends on build, test, and coverage
* overkill: Run **all** tests (no coverage)
* generateEclipseClasspath: Generates a `.classpath` file which is understandable by Eclipse and VS Code to make development easier. (This should ideally be run prior to opening ACCP in your IDE.)
* single_test: Runs a single unit test. The test is selected with the Java system property `SINGLE_TEST`. For example: `./gradlew single_test -DSINGLE_TEST=com.amazon.corretto.crypto.provider.test.EcGenTest`
  (You may need to do a clean build when switching between selected tests.)

## Configuration
There are several ways to configure the ACCP as the highest priority provider in Java.

### Code
Run the following method early in program start up: `com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider.install()`

### Via Security Properties
Add the following Java property to your programs command line: `-Djava.security.properties=/path/to/amazon-corretto-crypto-provider.security` where amazon-corretto-crypto-provider.security is downloaded from
[amazon-corretto-crypto-provider.security](./etc/amazon-corretto-crypto-provider.security) (for JDK versions older than JDK15)
or [amazon-corretto-crypto-provider-jdk15.security](./etc/amazon-corretto-crypto-provider-jdk15.security) (for JDK15 or newer)
in our repository.

### Modify the JVM settings
Modify the `java.security` file provided by your JVM so that the highest priority provider is the Amazon Corretto Crypto Provider.
Look at [amazon-corretto-crypto-provider.security](./etc/amazon-corretto-crypto-provider.security) (JDKs 11 and older)
or [amazon-corretto-crypto-provider-jdk15.security](./etc/amazon-corretto-crypto-provider-modules.security) (for JDKs newer than 11)
for an example of what this change will look like.

### Verification (Optional)
If you want to check to verify that ACCP is properly working on your system, you can do any of the following:
1. Verify that the highest priority provider actually is ACCP:
```java
if (Cipher.getInstance("AES/GCM/NoPadding").getProvider().getName().equals(AmazonCorrettoCryptoProvider.PROVIDER_NAME)) {
    // Successfully installed
}
```
2. Ask ACCP about its health
```java
if (AmazonCorrettoCryptoProvider.INSTANCE.getLoadingError() == null && AmazonCorrettoCryptoProvider.INSTANCE.runSelfTests().equals(SelfTestStatus.PASSED)) {
    // Successfully installed
}
```
3. Assert that ACCP is healthy and throw a `RuntimeCryptoException` if it isn't.
We generally do not recommend this solution as we believe that gracefully falling back to other providers is usually the better option.
```java
AmazonCorrettoCryptoProvider.INSTANCE.assertHealthy();
```

### Other system properties
ACCP can be configured via several system properties.
None of these should be needed for standard deployments and we recommend not touching them.
They are of most use to developers needing to test ACCP or experiment with benchmarking.
These are all read early in the load process and may be cached so any changes to them made from within Java may not be respected.
Thus, these should all be set on the JVM command line using `-D`.

* `com.amazon.corretto.crypto.provider.extrachecks`
   Adds exta cryptographic consistency checks which are not necessary on standard systems.
   These checks may be computationally expensive and are not normally relevant.
   See `ExtraCheck.java` for values and more information.
   (Also accepts "ALL" as a value to enable all flags and "help" to print out all flags to STDERR.)
* `com.amazon.corretto.crypto.provider.debug`
   Enables extra debugging behavior.
   These behaviors may be computationally expensive, produce additional output, or otherwise change the behavior of ACCP.
   No values here will lower the security of ACCP or cause it to give incorrect results.
   See `DebugFlag.java` for values and more information.
   (Also accepts "ALL" as a value to enable all flags and "help" to print out all flags to STDERR.)
* `com.amazon.corretto.crypto.provider.useExternalLib`
   Takes in `true` or `false` (defaults to `false`).
   If `true` then ACCP skips trying to load the native library bundled within its JAR and goes directly to the system library path.
* `com.amazon.corretto.crypto.provider.janitor.stripes`
   Takes *positive integer value* which is the requested minimum number of "stripes" used by the `Janitor` for dividing cleaning tasks (messes) among its workers.
   (Current behavior is to default this value to 4 times the CPU core count and then round the value up to the nearest power of two.)
   See `Janitor.java` for for more information.
* `com.amazon.corretto.crypto.provider.cacheselftestresults` Takes in `true` or `false`
  (defaults to `true`). If set to `true`, the results of running tests are cached,
  and the subsequent calls to `AmazonCorrettoCryptoProvider::runSelfTests`
  would avoid re-running tests; otherwise, each call to `AmazonCorrettoCryptoProvider::runSelfTests`
  re-run the tests.


# License
This library is licensed under the Apache 2.0 license although portions of this
product include software licensed under the [dual OpenSSL and SSLeay
license](https://www.openssl.org/source/license.html).  This product includes
software developed by the OpenSSL Project for use in the OpenSSL Toolkit
([http://www.openssl.org](http://www.openssl.org/)), as well as cryptographic
software written by Eric Young (eay@cryptsoft.com).

As of version 2.0.0, our backing native cryptographic library (now AWS-LC) also
has some code published under
[MIT](https://github.com/awslabs/aws-lc/blob/main/LICENSE#L164), [Google's
ISC](https://github.com/awslabs/aws-lc/blob/main/LICENSE#L147), and [3-clause
BSD](https://github.com/awslabs/aws-lc/blob/main/LICENSE#L188) licenses (among
others). Please see AWS-LC's `LICENSE` file for full details.
