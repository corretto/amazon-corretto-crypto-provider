# Amazon Corretto Crypto Provider
The Amazon Corretto Crypto Provider (ACCP) is a collection of high-performance cryptographic implementations exposed via the standard [JCA/JCE](https://docs.oracle.com/en/java/javase/11/security/java-cryptography-architecture-jca-reference-guide.html) interfaces.
This means that it can be used as a drop in replacement for many different Java applications.
Currently algorithms are primarily backed by OpenSSL's implementations (1.1.1g as of ACCP 1.5.0) but this may change in the future.

[Security issue notifications](./CONTRIBUTING.md#security-issue-notifications)


## Build Status
Please be aware that "Overkill" tests are known to be flakey

| Build Name | master branch | develop branch |
| ---------- | ------------- | -------------- |
| Unit Tests | ![Build Badge](https://codebuild.us-west-2.amazonaws.com/badges?uuid=eyJlbmNyeXB0ZWREYXRhIjoiMVYvdkw0MjJrcWJjdzc4TlNLcjdacGZDRVlWS0I2d1F1dThPM2RkNDZOVDlUMVJjU2o3TlAyTFZ2SlhtK1RnRm9LN09ySURjN2RYbjN3RmQ3bmFUZTBZPSIsIml2UGFyYW1ldGVyU3BlYyI6Inp3RWNaSXJtWVhISVUxU28iLCJtYXRlcmlhbFNldFNlcmlhbCI6MX0%3D&branch=master) | ![Build Badge](https://codebuild.us-west-2.amazonaws.com/badges?uuid=eyJlbmNyeXB0ZWREYXRhIjoiMVYvdkw0MjJrcWJjdzc4TlNLcjdacGZDRVlWS0I2d1F1dThPM2RkNDZOVDlUMVJjU2o3TlAyTFZ2SlhtK1RnRm9LN09ySURjN2RYbjN3RmQ3bmFUZTBZPSIsIml2UGFyYW1ldGVyU3BlYyI6Inp3RWNaSXJtWVhISVUxU28iLCJtYXRlcmlhbFNldFNlcmlhbCI6MX0%3D&branch=develop) |
| Integ Tests | ![Build Badge](https://codebuild.us-west-2.amazonaws.com/badges?uuid=eyJlbmNyeXB0ZWREYXRhIjoiOHE2R2FnSVEwTDEvcTdUQXMxdkpuY1ROdFBveHNGM3U0Uk81UkJxaUY2U1MvS1pPaFBmZWZSZS9FZHM5U1V2MUc1NEkzWDlLbjFpYjRXQkVNQ050VWVvPSIsIml2UGFyYW1ldGVyU3BlYyI6IlkycVZtSjNCM25SOW9iWlgiLCJtYXRlcmlhbFNldFNlcmlhbCI6MX0%3D&branch=master) | ![Build Badge](https://codebuild.us-west-2.amazonaws.com/badges?uuid=eyJlbmNyeXB0ZWREYXRhIjoiOHE2R2FnSVEwTDEvcTdUQXMxdkpuY1ROdFBveHNGM3U0Uk81UkJxaUY2U1MvS1pPaFBmZWZSZS9FZHM5U1V2MUc1NEkzWDlLbjFpYjRXQkVNQ050VWVvPSIsIml2UGFyYW1ldGVyU3BlYyI6IlkycVZtSjNCM25SOW9iWlgiLCJtYXRlcmlhbFNldFNlcmlhbCI6MX0%3D&branch=develop) |
| Dieharder Tests | ![Build Badge](https://codebuild.us-west-2.amazonaws.com/badges?uuid=eyJlbmNyeXB0ZWREYXRhIjoia0IxUitySWNCQ2hCSGN0T0xUZjV2VzNWb1hTZ2ljMzN1dnJienNQbFZRUGtTOXZJKzJmMUVvZk12MTM2enlWb1lmTTcrdUVlZStNYWx5V0taeU9naG1NPSIsIml2UGFyYW1ldGVyU3BlYyI6ImxIMlNyM1IzUHpFalAwQ20iLCJtYXRlcmlhbFNldFNlcmlhbCI6MX0%3D&branch=master) | ![Build Badge](https://codebuild.us-west-2.amazonaws.com/badges?uuid=eyJlbmNyeXB0ZWREYXRhIjoia0IxUitySWNCQ2hCSGN0T0xUZjV2VzNWb1hTZ2ljMzN1dnJienNQbFZRUGtTOXZJKzJmMUVvZk12MTM2enlWb1lmTTcrdUVlZStNYWx5V0taeU9naG1NPSIsIml2UGFyYW1ldGVyU3BlYyI6ImxIMlNyM1IzUHpFalAwQ20iLCJtYXRlcmlhbFNldFNlcmlhbCI6MX0%3D&branch=develop) |
| Overkill | ![Build Badge](https://codebuild.us-west-2.amazonaws.com/badges?uuid=eyJlbmNyeXB0ZWREYXRhIjoiQjBiWm5McXZDazZ3MnI3UnRjZWJJZkZRM200L2tqM3E0ZWJjVmc1RHBXbWRuMWZ5dHdXU3A0Tms4ZEVJNDBDdWdnQWdnTjkxTXBmNGxIWElVTFNPU1VVPSIsIml2UGFyYW1ldGVyU3BlYyI6Ikh5M0lRSHdFSkdoUC9hb2YiLCJtYXRlcmlhbFNldFNlcmlhbCI6MX0%3D&branch=master) | ![Build Badge](https://codebuild.us-west-2.amazonaws.com/badges?uuid=eyJlbmNyeXB0ZWREYXRhIjoiQjBiWm5McXZDazZ3MnI3UnRjZWJJZkZRM200L2tqM3E0ZWJjVmc1RHBXbWRuMWZ5dHdXU3A0Tms4ZEVJNDBDdWdnQWdnTjkxTXBmNGxIWElVTFNPU1VVPSIsIml2UGFyYW1ldGVyU3BlYyI6Ikh5M0lRSHdFSkdoUC9hb2YiLCJtYXRlcmlhbFNldFNlcmlhbCI6MX0%3D&branch=develop) |

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
* RSA/ECB/NoPadding
* RSA/ECB/PKCS1Padding
* RSA/ECB/OAEPWithSHA-1AndMGF1Padding

Signature algorithms:
* SHA1withRSA
* SHA224withRSA
* SHA256withRSA
* SHA384withRSA
* SHA512withRSA
* NONEwithDSA
* SHA1withDSA
* SHA224withDSA
* SHA256withDSA
* SHA384withDSA
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

KeyPairGenerator algorithms:
* EC
* RSA

KeyAgreement:
* DH
* DiffieHellman (same as DH)
* ECDH

SecureRandom algorithms:
* NIST800-90A/AES-CTR-256 (Used as the default and only enabled if your CPU supports RDRAND)


# Compatibility & Requirements
ACCP has the following requirements:
* JDK8 or newer (This includes both OracleJDK and [Amazon Corretto](https://aws.amazon.com/corretto/))
* 64-bit Linux running on x86_64 (also known as x64 or AMD64)

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
classifier. You'll get an empty package otherwise.

### Maven
Add the following to your `pom.xml` or wherever you configure your Maven dependencies.
This will instruct it to use the most recent 1.x version of ACCP.
For more information, please see [VERSIONING.rst](https://github.com/corretto/amazon-corretto-crypto-provider/blob/develop/VERSIONING.rst).

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

Building this provider requires a 64 bit Linux build system with the following prerequisites installed:
* OpenJDK 10 or newer
* [cmake](https://cmake.org/) 3.8 or newer
* C++ build chain
* [lcov](http://ltp.sourceforge.net/coverage/lcov.php) for coverage metrics
* [dieharder](http://webhome.phy.duke.edu/~rgb/General/dieharder.php) for entropy tests

1. Download the repository through a git clone
2. Run `./gradlew release`
3. The resulting jar is in `build/lib`

##### All targets
* clean: Remove all artifacts except OpenSSL dependencies
* deep_clean: Remove the entire `build/` directory including OpenSSL dependencies
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

## Configuration
There are several ways to configure the ACCP as the highest priority provider in Java.

### Code
Run the following method early in program start up: `com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider.install()`

### Via Security Properties
Add the following Java property to your programs command line: `-Djava.security.properties=/path/to/amazon-corretto-crypto-provider.security` where amazon-corretto-crypto-provider.security is [downloaded from](https://github.com/corretto/amazon-corretto-crypto-provider/blob/master/etc/amazon-corretto-crypto-provider.security) our repository.

### Modify the JVM settings
Modify the `java.security` file provided by your JVM so that the highest priority provider is the Amazon Corretto Crypto Provider. Look at [amazon-corretto-crypto-provider.security](https://github.com/corretto/amazon-corretto-crypto-provider/blob/master/etc/amazon-corretto-crypto-provider.security) for an example of what this change will look like.

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

# License
This library is licensed under the Apache 2.0 license although portions of this product include software licensed under the
[dual OpenSSL and SSLeay license](https://www.openssl.org/source/license.html).
Specifically, this product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit ([http://www.openssl.org](http://www.openssl.org/))
and this product also includes cryptographic software written by Eric Young (eay@cryptsoft.com).

