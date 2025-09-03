# Amazon Corretto Crypto Provider
The Amazon Corretto Crypto Provider (ACCP) is a collection of high-performance cryptographic implementations exposed via the standard [JCA/JCE](https://docs.oracle.com/en/java/javase/11/security/java-cryptography-architecture-jca-reference-guide.html) interfaces.
This means that it can be used as a drop in replacement for many different Java applications.
(Differences from the default OpenJDK implementations are [documented here](./DIFFERENCES.md).)
As of 2.0.0, algorithms exposed by ACCP are primarily backed by [AWS-LC](https://github.com/awslabs/aws-lc)'s implementations.

[Security issue notifications](./CONTRIBUTING.md#security-issue-notifications)

## Build Status

| Build Name | `main` branch |
| ---------- |---------------|
| Linux x86_64 | ![](https://codebuild.us-west-2.amazonaws.com/badges?uuid=eyJlbmNyeXB0ZWREYXRhIjoiRW4zZUhmeHlJbHRVQnNBZGZEbVJUa0pOK0J0MmtnNVB2dVZZSWhLbUtaNWYxNG96WWg4emN1SjJKL3VSUk9obFl0MnBtajBxejlVWDFiR3ppZGd3U1lrPSIsIml2UGFyYW1ldGVyU3BlYyI6IkFsUkpiMDRkRjZQb1U3Ly8iLCJtYXRlcmlhbFNldFNlcmlhbCI6MX0%3D&branch=main) |
| Linux aarch64 | ![](https://codebuild.us-west-2.amazonaws.com/badges?uuid=eyJlbmNyeXB0ZWREYXRhIjoiMEVNSXhZYmdEOWFrcE1HdE9nQmdwVlZFZXRYVnloc05TMXhoZ0tTVUQ1ZlMzeWRrZTArSUxUdzY2RVJRbUtXak5zU2ZCamJBS3JxUEFxZFJ2ZVNkcGVNPSIsIml2UGFyYW1ldGVyU3BlYyI6Ii80UEZpYWc2RjJZLzZDQ0wiLCJtYXRlcmlhbFNldFNlcmlhbCI6MX0%3D&branch=main) |

## Performance Benchmarks

We provide complete benchmarking data from our [benchmarking suite](./benchmarks/README.md) for the current tip of `main`.

| Build Name | Data | EC2 Instance Type |
| - | - | - |
| Linux x86_64 | [link](https://d1veyo88e7gsuw.cloudfront.net/c7ixlarge/index.html) | c7i.xlarge |
| Linux aarch64 | [link](https://d1veyo88e7gsuw.cloudfront.net/c8gxlarge/index.html) | c8g.xlarge |

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
* AES_\<n\>/GCM/NoPadding, where n can be 128, or 256
* AES/KWP/NoPadding
* AES/XTS/NoPadding
* AES/CBC/NoPadding
  * AES_\<n\>/CBC/NoPadding, where n can be 128, 192, or 256
* AES/CBC/PKCS5Padding
  * AES_\<n\>/CBC/PKCS5Padding, where n can be 128, 192, or 256
  * PKCS7Padding is also accepted with AES/CBC and it is treated the same as PKCS5.
* AES/CBC/ISO10126Padding
    * AES_\<n\>/CBC/ISO10126Padding, where n can be 128, 192, or 256
* AES/CFB/NoPadding
    * AES_\<n\>/CFB/NoPadding, where n can be 128 or 256
* RSA/ECB/NoPadding
* RSA/ECB/PKCS1Padding
* RSA/ECB/OAEPPadding
* RSA/ECB/OAEPWithSHA-1AndMGF1Padding
* RSA/ECB/OAEPWithSHA1AndMGF1Padding

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
* ED25519 (JDK 15+)
* ED25519ph (JDK 15+)
* ML-DSA
* ML-DSA-ExtMu

KeyPairGenerator:
* EC
* RSA
* ED25519 (JDK 15+)
* X25519 (JDK 11+)

KeyGenerator:
* AES

KeyAgreement:
* ECDH

SecretKeyFactory:
* HkdfWithHmacSHA1
* HkdfWithHmacSHA256
* HkdfWithHmacSHA384
* HkdfWithHmacSHA512
* ConcatenationKdfWithSHA256
* ConcatenationKdfWithSHA384
* ConcatenationKdfWithSHA512
* ConcatenationKdfWithHmacSHA256
* ConcatenationKdfWithHmacSHA512
* CounterKdfWithHmacSHA256
* CounterKdfWithHmacSHA384
* CounterKdfWithHmacSHA512

SecureRandom:
* ACCP's SecureRandom uses [AWS-LC's DRBG implementation](https://github.com/aws/aws-lc/blob/main/crypto/fipsmodule/rand/rand.c).

KeyFactory:
* EC
* RSA
* ED25519 (JDK 15+). Please refer to [system properties](https://github.com/corretto/amazon-corretto-crypto-provider#other-system-properties) for more information.

AlgorithmParameters:
* EC. Please refer to [system properties](https://github.com/corretto/amazon-corretto-crypto-provider#other-system-properties) for more information.

Mac algorithms with precomputed key and associated secret key factories (expert use only, refer to [HMAC with Precomputed Key](https://github.com/corretto/amazon-corretto-crypto-provider#HMAC-with-Precomputed-Key) for more information):
* HmacSHA512WithPrecomputedKey
* HmacSHA384WithPrecomputedKey
* HmacSHA256WithPrecomputedKey
* HmacSHA1WithPrecomputedKey
* HmacMD5WithPrecomputedKey

# Notes on ACCP-FIPS
ACCP-FIPS is a variation of ACCP which uses AWS-LC-FIPS 2.x as its cryptographic module. This version of AWS-LC-FIPS has FIPS certificate [4816](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4816).

Version 2.3.0 is the first release of ACCP-FIPS. The Maven coordinates for
ACCP-FIPS are the same as ACCP with one difference that ACCP-FIPS's
artifact ID is `AmazonCorrettoCryptoProvider-FIPS`.

The table below shows which AWS-LC and AWS-LC-FIPS release versions are used in each ACCP(-FIPS) release.
ACCP did not track a FIPS branch/release version of AWS-LC until ACCP v2.3.0. Before then, ACCP-FIPS simply built its tracked AWS-LC commit in FIPS mode.

| ACCP(-FIPS) version | AWS-LC version | AWS-LC-FIPS version |
|---------------------|----------------|---------------------|
| 2.0.0               | 1.4.0          | ---                 |
| 2.1.0               | 1.5.0          | ---                 |
| 2.2.0               | 1.5.0          | ---                 |
| 2.3.0               | 1.5.0          | 2.0.0               |
| 2.3.1               | 1.15.0         | 2.0.0               |
| 2.3.2               | 1.16.0         | 2.0.0               |
| 2.3.3               | 1.17.0         | 2.0.2               |
| 2.4.0               | 1.30.1         | 2.0.13              |
| 2.4.1               | 1.30.1         | 2.0.13              |
| 2.5.0               | 1.47.0         | 3.0.0               |
| 2.6.0               | 1.48.2         | 3.0.0               |

Notable differences between ACCP and ACCP-FIPS:
* ACCP uses [the latest release of AWS-LC](https://github.com/aws/aws-lc/releases), whereas, ACCP-FIPS uses [the fips-2022-11-02 branch of AWS-LC](https://github.com/aws/aws-lc/tree/fips-2022-11-02).
* ACCP-FIPS builds AWS-LC in FIPS mode by passing `-DFIPS=1` when configuring AWS-LC's build.
* For details about the FIPS module of AWS-LC in FIPS mode, including the entropy sources used, see the [AWS-LC FIPS.md documentation](https://github.com/aws/aws-lc/blob/main/crypto/fipsmodule/FIPS.md).
* In FIPS-mode, RSA keys are limited to 2048, 3072, or 4096 bits in size with public exponent F4.
* Due to the fact that an older branch of AWS-LC is used in FIPS-mode, there will be performance differences between ACCP and ACCP-FIPS. We highly recommend performing detailed performance testing of your application if you choose to experiment with ACCP-FIPS.
* Between versions 2.1.0 and 2.3.3 (inclusive), ACCP-FIPS does not register SecureRandom by default due to the performance of AWS-LC’s entropy source in FIPS-mode, with older versions of AWS-LC. Since version 2.4.0, ACCP-FIPS behaves as ACCP: it registers SecureRandom from AWS-LC by default. [A system property](https://github.com/corretto/amazon-corretto-crypto-provider#other-system-properties) is available to change the default behavior.

ACCP-FIPS is only supported on the following platforms:

| Platform | FIPS support since version |
|----------|----------------------------|
| `linux-x86_64` | 2.3.0 |
| `linux-aarch_64` | 2.3.0 |

# Compatibility & Requirements
ACCP has the following requirements:
* JDK8 or newer (This includes both OracleJDK and [Amazon Corretto](https://aws.amazon.com/corretto/))
* Linux (x86-64 or arm64) or MacOs running on x86_64 (also known as x64 or AMD64)

ACCP comes bundled with AWS-LC's `libcrypto.so`, so it is not necessary to install AWS-LC on the host or container where you run your application.

If ACCP is used/installed on a system it does not support, it will disable itself and the JVM will behave as if ACCP weren't installed at all.

# Using the provider
## Installation
Installing via Maven or Gradle is the easiest way to get ACCP and ensure you
will always have the most recent version. We strongly recommend you always pull
in the latest version for best performance and bug-fixes.

Whether you're using Maven, Gradle, or some other build system that also pulls
packages from Maven Central, it's important to specify a classifier, otherwise,
one would get an empty package. The possible classifiers are as follows:

| Classifier | Support since version | FIPS support since version |
|------------|-----------------------|----------------------------|
| `linux-x86_64` | 1.0.0 | 2.3.0 |
| `linux-aarch_64` | 2.0.0 | 2.3.0 |
| `osx-x86_64` | 2.3.2 | Not supported |
| `osx-aarch_64` | 2.3.3 | Not supported |


Regardless of how you acquire ACCP (Maven, manual build, etc.) you will still need to follow the guidance in the [Configuration section](#configuration) to enable ACCP in your application.

### Maven
Add the following to your `pom.xml` or wherever you configure your Maven dependencies.
This will instruct it to use the latest `2.x` version of ACCP for Linux x86-64 platform.
For more information, please see [VERSIONING.rst](https://github.com/corretto/amazon-corretto-crypto-provider/blob/main/VERSIONING.rst).

```xml
<dependency>
  <groupId>software.amazon.cryptools</groupId>
  <artifactId>AmazonCorrettoCryptoProvider</artifactId>
  <version>[2.0, 3.0)</version>
  <classifier>linux-x86_64</classifier>
</dependency>
```

The artifactId for FIPS builds is `AmazonCorrettoCryptoProvider-FIPS`.

ACCP artifacts on Maven can be verified using the following PGP keys:

| ACCP Version  | PGP Key ID       | Key Server |
|---------------|------------------|------------|
| 1.x | 6F189046CEE0B2C1 | keyserver.ubuntu.com |
| 2.x | 5EFEEFE6BD0BD916 | keyserver.ubuntu.com |


### Gradle

Add something like following to your `build.gradle` file.

```groovy
dependencies {
    implementation 'software.amazon.cryptools:AmazonCorrettoCryptoProvider:2.+:linux-x86_64'
}
```

If you already have a `dependencies` block in your `build.gradle`, you can add the ACCP line to your existing block.

The above sample configuration assumes you're using the `linux-x86_64` platform. If you're using another platform, please refer to the "Installation" parent section above and substitute appropriately.

For Gradle builds, the [os-detector plugin](https://github.com/google/osdetector-gradle-plugin)
can be used to avoid explicitly specifying the platform.
[Here](https://github.com/corretto/amazon-corretto-crypto-provider/blob/f1d54b34cf4765789314941dbeefdafd35a4da58/examples/gradle-kt-dsl/lib/build.gradle.kts#L30)
is an example.

For more version information, please see [VERSIONING.rst](https://github.com/corretto/amazon-corretto-crypto-provider/blob/main/VERSIONING.rst).

### Bundle ACCP with JDK
We provide two scripts that allow one to add ACCP to their JDKs: one for JDK8 and one for JDKs 11+.
Please note that these scripts are provided as examples and for testing only.

These scripts take the version of ACCP and the classifier as input. Optionally, one can pass `-FIPS`
as the third argument to bundle the FIPS artifacts. To use these scripts, please set `JAVA_HOME` to
the path of your desired JDK.

Usage example:
```bash
./bin/bundle-accp.sh 2.3.3 linux-x86_64
```

To find the available versions and classifiers, please check out Maven central.

Some notes on the bundling scripts:
* One needs to run the bundling script only once.
* The bundling is not idempotent: running the script on a JDK that has ACCP bundled in it could result in undefined behavior.
* There is no unbundling. Please do a fresh install of the JDK if you need to remove ACCP from your JDK.

### Manual
Manual installation requires acquiring the provider and adding it to your classpath.
You can either download a prebuilt version of the provider or build it yourself.
Adding a jar to your classpath is highly application and build-system dependent and we cannot provide specific guidance.

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
* [Go](https://golang.org/dl/) 1.18 or later is required. 1.18 or later is the minimum required
  version to build AWS-LC, 1.20 or later is needed in order to run AWS-LC's test suite. If not 
  found by CMake, the go executable may be configured explicitly by setting `GO_EXECUTABLE`.

1. Download the repository via `git clone --recurse-submodules`
2. Run `./gradlew release`
3. The resulting jar is in `build/lib`

#### Repackaging ACCP into Uber/Fat Jars
Please be aware that repackaging ACCP's published Jar files from Maven into your own "uber" or "fat" JAR file may not 
work on OracleJDK. The OracleJDK requires that JCE providers be cryptographically signed by a trusted certificate. The 
JARs we publish via Maven and our official [releases](https://github.com/corretto/amazon-corretto-crypto-provider/releases) are signed by our private key, but yours will not be.

Depending on how ACCP is repackaged, ACCP's existing signature may be invalidated, and you may receive one of the
following exceptions: 
 - `java.util.jar.JarException: The JCE Provider file is not signed.`
 - `java.lang.SecurityException: JCE cannot authenticate the provider`
 - `java.security.NoSuchProviderException: JCE cannot authenticate the provider`

If you receive one of these exceptions, then you will need to evaluate if any of the following options will work for your application and environment:
1. Exclude ACCP from your repackaging process, keeping ACCP's jar file unmodified, and deploying both your uber jar and ACCP jar as separate jar files.
2. Use a non-standard Java ClassLoader that allows loading a "jar of jars" (such as [Spring-boot's NestedJarFile](https://docs.spring.io/spring-boot/docs/current/reference/html/executable-jar.html#appendix.executable-jar.jarfile-class)), and copy ACCP's Jar file into the parent Jar file so that ACCP's JCE signature remains intact.
3. Migrate to a different JDK (eg OpenJDK or CorrettoJDK) that does not require that JCE providers be signed.
4. [Obtain your own JCE Code Signing Certificate](https://www.oracle.com/java/technologies/javase/getcodesigningcertificate.html) and sign your repackaged Jar.

#### Building ACCP in FIPS mode
There are two possible flags which can be provided to `gradlew` to build ACCP in FIPS mode:
- `-DFIPS=true`: This causes ACCP to be built with AWS-LC-FIPS as its underlying crypto library. The exact version of AWS-LC-FIPS used is specified in our [build.gradle](https://github.com/corretto/amazon-corretto-crypto-provider/blob/main/build.gradle#L28) file. Refer to the [AWS-LC FIPS documentation](https://github.com/aws/aws-lc/blob/main/crypto/fipsmodule/FIPS.md) for the latest FIPS validation and certification status of each version.
- `-DEXPERIMENTAL_FIPS=true`: This causes ACCP to be built with the `main` branch of AWS-LC, built in FIPS mode, as its underlying crypto library. This variation of FIPS mode allows one to experiment with the latest APIs and features in AWS-LC that have not yet made it onto a FIPS branch/release.

The following illustration depicts the difference these FIPS mode build options.
```
                           -DEXPERIMENTAL_FIPS=true
                                      |
                                      ↓
AWS-LC [■]───[■]───[■]───[■]───[■]───[■]  main
                 \
                  [■]───[■]  AWS-LC-FIPS-X.Y.Z
                         ↑
                         |
                   -DFIPS=true
```

When changing between FIPS and non-FIPS builds, be sure to do a full `clean` of your build environment.

#### All targets
* clean: Remove all artifacts except AWS-LC build artifacts
* deep_clean: Remove the entire `build/` directory including build artifacts from AWS-LC dependencies
* build: Build the library
* test: Run unit tests
* test_extra_checks: Run unit tests with extra (slow) cryptographic checks enabled
* test_integration: Run integration tests
* test_integration_extra_checks: Run integration tests with extra (slow) cryptographic checks enabled
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
or [amazon-corretto-crypto-provider-jdk15.security](./etc/amazon-corretto-crypto-provider-jdk15.security) (for JDKs newer than 11)
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
None of these should be needed for standard deployments, and we recommend not touching them.
They are of most use to developers needing to test ACCP or experiment with benchmarking.
These are all read early in the load process and may be cached so any changes to them made from within Java may not be respected.
Thus, these should all be set on the JVM command line using `-D`.

* `com.amazon.corretto.crypto.provider.extrachecks`
   Adds extra cryptographic consistency checks which are not necessary on standard systems.
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
   See `Janitor.java` for more information.
* `com.amazon.corretto.crypto.provider.cacheselftestresults` Takes in `true` or `false`
  (defaults to `true`). If set to `true`, the results of running tests are cached,
  and the subsequent calls to `AmazonCorrettoCryptoProvider::runSelfTests`
  would avoid re-running tests; otherwise, each call to `AmazonCorrettoCryptoProvider::runSelfTests`
  re-run the tests.
* `com.amazon.corretto.crypto.provider.registerEcParams`
  Takes in `true` or `false` (defaults to `false`).
  If `true`, then ACCP will register its EC-flavored AlgorithmParameters implementation on startup.
  Else, the JCA will get the implementation from another registered provider (usually stock JCE).
  Using JCE's implementation is generally recommended unless using ACCP as a standalone provider
  Callers can choose to register ACCP's implementation at runtime with a call to `AmazonCorrettoCryptoProvider.registerEcParams()`
* `com.amazon.corretto.crypto.provider.registerSecureRandom`
  Takes in `true` or `false` (defaults to `true`).
  If `true`, then ACCP will register a SecureRandom implementation (`LibCryptoRng`) backed by AWS-LC.
  Else, ACCP will not register a SecureRandom implementation, meaning that the JCA will source SecureRandom instances from another registered provider. AWS-LC will still use its internal DRBG for key generation and other operations requiring secure pseudo-randomness.
  Before version 2.4.0, default was `false` for FIPS builds.
* `com.amazon.corretto.crypto.provider.nativeContextReleaseStrategy`
  Takes in `HYBRID`, `LAZY`, or `EAGER` (defaults to `HYBRID`). This property only affects
  AES-GCM cipher for now. AES-GCM associates a native object of type `EVP_CIPHER_CTX`
  to each `Cipher` object. This property allows users to control the strategy for releasing
  the native object.
  * `HYBRID` (default): the structure is released eagerly, unless the same AES key is used. This is the
     default behavior, and it is consistent with prior releases of ACCP.
  * `LAZY`: preserve the native object and do not release while the `Cipher` object is not garbage collected.
  * `EAGER`: release the native object as soon as possible, regardless of using the same key or not.
  Our recommendation is to set this property to `EAGER` if `Cipher` objects are discarded
  after use and caching of `Cipher` objects is not needed. When reusing the same `Cipher`
  object, it would be beneficial to set this system property to `LAZY` so that different
  encryption/decryption operations would not require allocation and release of `EVP_CIPHER_CTX`
  structure. A common use case would be having long-running threads that each would get its
  own instance of `Cipher` class.
* `com.amazon.corretto.crypto.provider.tmpdir`
   Allows one to set the temporary directory used by ACCP when loading native libraries.
   If this system property is not defined, the system property `java.io.tmpdir` is used.
* `com.amazon.corretto.crypto.provider.registerEdKeyFactory`
  Takes in `true` or `false` (defaults to `false`).
  If `true` and JDK version is 15+, then ACCP will register its Ed25519 related KeyFactory classes.
  The keys produced by ACCP's KeyFactory services for Ed25519 do not implement [EdECKey](https://docs.oracle.com/en/java/javase/17/docs//api/java.base/java/security/interfaces/EdECKey.html)
  interface, and as a result, they cannot be used by other providers. Consider setting this property
  to `true` if the keys are only used by other ACCP services AND they are not type cast to `EdECKey`.
  It is worth noting that the key generated by KeyFactory service of SunEC can be used by ACCP services
  such as Signature.

## Build Parameters

ACCP supports build-time parameters that control compilation behavior and compatibility. 
#### Target JDK Version
The runtime target that ACCP will be targeting on specifies the minimum JDK version required to run the program and determines which language features and APIs can be used. This can be specified for ACCP using the `-DTARGET_JDK_VERSION` flag when compiling ACCP from source.  For example, to target JDK 17 compatibility when compiling with gradle, you would use: <br>
<br> `./gradlew release -DTARGET_JDK_VERSION=17`.\
<br>Build-time JDK is the version of Java installed on your build machine that actually compiles the source code. You can use a newer build-time JDK to target an older runtime JDK, but you cannot use an older build-time JDK to target a newer runtime JDK.

# Additional information

## HMAC with Precomputed Key

EXPERT use only. Most users of ACCP just need normal `HmacXXX` algorithms and not their `WithPrecomputedKey` variants.

The non-standard-JCA/JCE algorithms `HmacXXXWithPrecomputedKey` (where `XXX` is the digest name, e.g., `SHA384`) implement an optimization of HMAC described in NIST-FIPS-198-1 (Section 6) and in RFC2104 (Section 4).
They allow to generate a precomputed key for a given original key and a given HMAC algorithm, 
and then to use this precomputed key to compute HMAC (instead of the original key).
Only use these algorithms if you know you absolutely need them.

In more detail, the secret key factories `HmacXXXWithPrecomputedKey` allow to generate a precomputed key from a normal HMAC key.
The mac algorithms `HmacXXXWithPrecomputedKey` take a precomputed key instead of a normal HMAC key.
Precomputed keys must implement `SecretKeySpec` with format `RAW` and algorithm `HmacXXXWithPrecomputedKey`.

Implementation uses AWS-LC functions `HMAC_set_precomputed_key_export`, `HMAC_get_precomputed_key`, and `HMAC_Init_from_precomputed_key`.

See [example HmacWithPrecomputedKey](./examples/lib/src/test/kotlin/com/amazon/corretto/crypto/examples/HmacWithPrecomputedKey.kt).

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
