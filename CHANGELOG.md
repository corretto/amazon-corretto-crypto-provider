# Changelog

## 2.0.0 (Unreleased)

### Overview
This is a new major release of ACCP. We provide build artifacts for Linux-x86
and Linux-aarch64, which can be accessed either from the release section on
Github, or via Maven Central.

This version uses [AWS-LC](https://github.com/awslabs/aws-lc/) instead of
OpenSSL (version 1.1.1j) as the underlying cryptographic library. The switch
provides advantages over the previous version of ACCP, such as improved
performance due to optimized assembly implementations of some cryptographic
algorithms in AWS-LC. These optimizations are beneficial for AWS Graviton users
as well as x86 based platforms; moreover, rigorous testing and formal
verification in AWS-LC’s development lifecycle reduces the risk of security
vulnerabilities.

This version is not backward compatible and the differences may affect your
application. Some major features, such as non-EC DSA and non-EC DH key exchange
algorithms, are removed. Other minor changes include, the implementation of the
SecureRandom relies on AWS-LC’s DRBG and the name is changed from
`NIST800-90A/AES-CTR-256` to `LibCryptoRng`.


This is a major release that includes some breaking changes. ACCP has switched to using [AWS-LC](https://github.com/awslabs/aws-lc/) instead of OpenSSL as the backing native crypto engine. This transition has improved the performance of ACCP. We have tried to keep the breaking changes minimal, but they have been deemed necessary. [Optimized assembly implementation of algorithms and the usage of formal verification in AWS-LC](https://github.com/awslabs/aws-lc/blob/main/README.md) are among the reasons for ACCP to switch from OpenSSL to AWS-LC. Some of these examples include dropping the support for non-EC DSA and DH key exchange algorithms; moreover, AWS-LC and OpenSSL are not 100% compatible. We have tried to keep the incompatibilities hidden from ACCP users, and we will deal with such scenarios case by case in the future.


### Major changes
* Support build and releases for Linux x86 and Linux aarch64
* Use [AWS-LC](https://github.com/awslabs/aws-lc/) as the as the underlying cryptographic library
* Drop support for (non-EC) DSA signatures
* Drop support for (non-EC) Diffie-Hellman key exchange
* Drop support for `secp192r1`, as well as most other non-NIST "legacy" curves
* Drop RDRAND-seeded, AES-CTR SecureRandom implementation
* Add SecureRandom implementation backed by AWS-LC DRBG
* Add AES key wrapping (a.k.a. KWP mode of AES)
* Add RSA OAEP cipher padding over SHA2 hashes
* Add RSA PSS signature padding over SHA1 and SHA2 hashes

### Minor changes
* Add support for AES Ciphers with specific key sizes (GCM, no padding)
* Track the AWS-LC dependency as a git submodule instead of downloaded tarball
* Improving the [configuration](https://github.com/corretto/amazon-corretto-crypto-provider#configuration) and system properties that control ACCP’s behavior
* External integration tests now skip certificate validation for expired certificates; this is to work around external sites which may have allowed their certificates to expire [PR #190](https://github.com/corretto/amazon-corretto-crypto-provider/pull/189)
* Allows developers to run `clang-tidy` against the source by passing `-DUSE_CLANG_TIDY=true` to gradlew
   * Example: `./gradlew -DUSE_CLANG_TIDY=true build`
   * This may require deleting `build/cmake` prior to running [PR #191](https://github.com/corretto/amazon-corretto-crypto-provider/pull/191)
* Add `KeyFactory` implementations for RSA and EC keys. This also includes our own implementations of keys for the same algorithms [PR #132](https://github.com/corretto/amazon-corretto-crypto-provider/pull/132)
* Added `amazon-corretto-crypto-provider-jdk15.security` to support JDK15+
* Add support for MacOS builds for development
* Add TLS 1.3 to local integ tests
* Fix libaccp builds for GCC 4.1.2
* Load AWS-LC using RPATH, restrict its symbols into a local object group

### Patches
* Improve zeroization of DRBG output. [PR #162](https://github.com/corretto/amazon-corretto-crypto-provider/pull/162)
* Correctly reject non-empty `PSource.PSpecified` values for RSA-OAEP.

## 1.6.1
### Patches
* Fix an issue where a race condition can cause ACCP's MessageDigest hashing algorithms to return the same value for different inputs [PR #157](https://github.com/corretto/amazon-corretto-crypto-provider/pull/157)

## 1.6.0
### Breaking Change
In accordance with our [versioning policy](https://github.com/corretto/amazon-corretto-crypto-provider/blob/master/VERSIONING.rst),
this release contains a low-risk breaking change. For details please see the [1.5.0](#150) section of this document.
This change only impacts libraries that generate EC keys using the
[KeyPairGenerator.initialize(int keysize)](https://docs.oracle.com/javase/8/docs/api/java/security/KeyPairGenerator.html#initialize-int-)
method.

### Improvements
* Stricter guarantees about which curves are used for EC key generation. [PR #127](https://github.com/corretto/amazon-corretto-crypto-provider/pull/127)
* Reduce timing signal from trimming zeros of TLSPremasterSecrets from DH KeyAgreement. [PR #129](https://github.com/corretto/amazon-corretto-crypto-provider/pull/129)
* Reuse state in `MessageDigest` to decrease object allocation rate. [PR #131](https://github.com/corretto/amazon-corretto-crypto-provider/pull/131)
* Now uses [OpenSSL 1.1.1j](https://www.openssl.org/source/openssl-1.1.1j.tar.gz). [PR #145](https://github.com/corretto/amazon-corretto-crypto-provider/pull/145)
  (ACCP is not impacted by [CVE-2020-1971](https://www.openssl.org/news/secadv/20201208.txt), [CVE-2021-23841](https://www.openssl.org/news/secadv/20210216.txt), or [CVE-2021-23839](https://www.openssl.org/news/secadv/20210216.txt) as ACCP does not use or expose any of the relevant functionality.
  ACCP is not impacted by [CVE-2021-23840](https://www.openssl.org/news/secadv/20210216.txt) as ACCP does not use the relevant functionality under the affected conditions.)

### Patches
* Add version gating to some tests introduced in 1.5.0 [PR #128](https://github.com/corretto/amazon-corretto-crypto-provider/pull/128)
* More accurate output size estimates from `Cipher.getOutputSize()` [PR #138](https://github.com/corretto/amazon-corretto-crypto-provider/pull/138)
* Validate that `AesGcmSpi` receives a non-null key on init to prevent unnecessarily late NPE [PR #146](https://github.com/corretto/amazon-corretto-crypto-provider/pull/146)
* Gracefully handle calling `Cipher.doFinal()` without any input bytes in `RsaCipher` [PR #147](https://github.com/corretto/amazon-corretto-crypto-provider/pull/147)

## 1.5.0
### Breaking Change Warning
In accordance with our [versioning policy](https://github.com/corretto/amazon-corretto-crypto-provider/blob/master/VERSIONING.rst),
we post warnings of upcoming changes that might cause compatibility issues.
As always, we expect that these changes will not impact the vast majority of consumers and can be picked up automatically provided you have good unit and integration changes.

Starting in ACCP version 1.6.0, EC key pair generation will throw an `InvalidParameterException` if initialized to a keysize that is not in the following list.
For these explicit sizes (only), ACCP behavior is unchanged. ACCP selects the the "secp*r1" curve that corresponds to the value. (For these values, its also the corresponding NIST prime curve).

**Supported keysize values:**
* 192
* 224
* 256
* 384
* 521

This means that the following code will start failing because it requests a keysize that is not on the list.
```java
KeyPairGenerator kg = KeyPairGenerator.getInstance("EC");
kg.initialize(160); // Throws an InvalidParameterException
```

We are making this change because the "SunEC" provider does not document its curve selection process for sizes other than those listed above and does not promise that it will continue to use the same curve selection process.
Without a consistency guarantee, developers can't use
[KeyPairGenerator.initialize(int keysize)](https://docs.oracle.com/javase/8/docs/api/java/security/KeyPairGenerator.html#initialize-int-)
safely (regardless of whether ACCP is used or not).

**We strongly recommend using**
**[KeyPairGenerator.initialize(AlgorithmParameterSpec params)](https://docs.oracle.com/javase/8/docs/api/java/security/KeyPairGenerator.html#initialize-java.security.spec.AlgorithmParameterSpec-)**
**with**
**[ECGenParameterSpec](https://docs.oracle.com/javase/8/docs/api/java/security/spec/ECGenParameterSpec.html)**
**to generate EC keys.**

From versions 1.2.0 through 1.5.0, ACCP selects the corresponding "secp*r1" curve for any keysize requested.
For the explicit sizes listed above this matches the SunEC behavior.
For other sizes, there are no documented guarantees of the SunEC behavior.

### Improvements
* Now uses [OpenSSL 1.1.1g](https://www.openssl.org/source/openssl-1.1.1g.tar.gz). [PR #108](https://github.com/corretto/amazon-corretto-crypto-provider/pull/108)
* Adds support for running a single test from the command line with the following syntax: [PR #113](https://github.com/corretto/amazon-corretto-crypto-provider/pull/113)

  `./gradlew single_test -DSINGLE_TEST=<Fully Qualified Classname>`

  For example: `./gradlew single_test -DSINGLE_TEST=com.amazon.corretto.crypto.provider.test.EcGenTest`

  You may need to do a clean build when changing tests.

### Patches
* Ensure unauthenticated plaintext is not released through either [Cipher.doFinal(byte[], int, int, byte[], int)](https://docs.oracle.com/javase/9/docs/api/javax/crypto/Cipher.html#doFinal-byte:A-int-int-byte:A-int-) or [Cipher.doFinal(ByteBuffer, ByteBuffer)](https://docs.oracle.com/javase/9/docs/api/javax/crypto/Cipher.html#doFinal-java.nio.ByteBuffer-java.nio.ByteBuffer-). [PR #123](https://github.com/corretto/amazon-corretto-crypto-provider/pull/123)
* Better handle HMAC keys with a `null` format. [PR #124](https://github.com/corretto/amazon-corretto-crypto-provider/pull/124)
* Throw `IllegalBlockSizeException` when attempting RSA encryption/decryption on data larger than the keysize. [PR #122](https://github.com/corretto/amazon-corretto-crypto-provider/pull/122)

### Maintenance
* Upgrade tests to JUnit5. [PR #111](https://github.com/corretto/amazon-corretto-crypto-provider/pull/111)
* Upgrade BouncyCastle test dependency 1.65. [PR #110](https://github.com/corretto/amazon-corretto-crypto-provider/pull/110)
* Add version gating to P1363 Format tests. [PR #112](https://github.com/corretto/amazon-corretto-crypto-provider/pull/112)
* Re-add support for very old x86_64 build-chains. [PR #112](https://github.com/corretto/amazon-corretto-crypto-provider/pull/112)

## 1.4.0
### Improvements
* Now uses [OpenSSL 1.1.1f](https://www.openssl.org/source/openssl-1.1.1f.tar.gz). [PR #97](https://github.com/corretto/amazon-corretto-crypto-provider/pull/97)
* **EXPERIMENTAL** support for aarch64 added. [PR #99](https://github.com/corretto/amazon-corretto-crypto-provider/pull/99)

### Maintenance
* Test code reuses instances of `SecureRandom` for better efficiency on platforms with slow entropy. [PR #96](https://github.com/corretto/amazon-corretto-crypto-provider/pull/96)

## 1.3.1

### Maintenance
* Add timestamping to signed jars. [PR #85](https://github.com/corretto/amazon-corretto-crypto-provider/pull/85)
* Create the `Janitor` in the `Loader` so that it gets a more logical and consistent `ThreadGroup`. [PR #87](https://github.com/corretto/amazon-corretto-crypto-provider/pull/87)
* Signed with new JCE signing certificate

## 1.3.0

### Improvements
* Now supports ECDSA signatures in IEEE P1363 Format. (Also known as "raw" or "plain".) [PR #75](https://github.com/corretto/amazon-corretto-crypto-provider/pull/75)
* Now allows cloning of `Mac` objects. [PR #78](https://github.com/corretto/amazon-corretto-crypto-provider/pull/78)

### Maintenance
* You can disable parallel execution of tests by setting the `ACCP_TEST_PARALLEL` environment variable to `false`

## 1.2.0

### Improvements
* Now uses [OpenSSL 1.1.1d](https://www.openssl.org/source/openssl-1.1.1d.tar.gz). [PR #60](https://github.com/corretto/amazon-corretto-crypto-provider/pull/60)

### Patches
* Detects stuck AMD Ryzen RDRAND and correctly treats as an error [PR #67](https://github.com/corretto/amazon-corretto-crypto-provider/pull/67)
* When initialized with an `int`,`KeyPairGenerator` for "EC" keys now always uses "secp*r1" curves.
  This matches the behavior of SunEC.
  **This changes the curves selected for 192 from secp192k1 to secp192r1/P-192, and curves selected for 256 from secp256k1 to secp256r1/P-256.**
  [PR #68](https://github.com/corretto/amazon-corretto-crypto-provider/pull/68)

### Maintenance
* The test output now contains a prefix indication whether the suite will fail. [PR #63](https://github.com/corretto/amazon-corretto-crypto-provider/pull/63)
* You can disable colored test output by setting the `ACCP_TEST_COLOR` environment variable to `false` [PR #64](https://github.com/corretto/amazon-corretto-crypto-provider/pull/64)

## 1.1.1

### Patches
* `amazon-corretto-crypto-provider.security` updated to work on both JDK8 and JDK9+ [PR #49](https://github.com/corretto/amazon-corretto-crypto-provider/pull/49)
* Improved performance of single-byte handling in message digests. [PR #53](https://github.com/corretto/amazon-corretto-crypto-provider/pull/53) and [PR #54](https://github.com/corretto/amazon-corretto-crypto-provider/pull/54)

### Maintenance
* Support using a different JDK for testing via the `TEST_JAVA_HOME` JVM property [PR #50](https://github.com/corretto/amazon-corretto-crypto-provider/pull/50)
* Clarify licensing [PR #55](https://github.com/corretto/amazon-corretto-crypto-provider/pull/55)

## 1.1.0

### Improvements
* Now supports DH key agreement for more than two parties.

### Patches
* Reject RSA key generation shorter than 512 bits
* Fix incorrect exception when SunJSSE validates RSA signatures backed by ACCP RSA
* Make the provider actually serializable to keep JTREG happy
* Moved property and resource access to inside PrivilegedAction blocks
* Throw `InvalidKeyException` when KeyAgreement and Signature gets `null` keys
* Throw `SignatureException` on corrupted signatures as required by the JCA/JCE

### Maintenance
* Changed logging level to eliminate output under normal usage.

## 1.0.4
### Maintenance
* Fix Java heap space issues in unit tests

## 1.0.3

### Patches
* Fix performance issue caused by always clearing the OpenSSL error stack
* Correctly clear OpenSSL error stack in failed signature verification

### Maintenance
* Make coverage fail if OpenSSL error stack isn't clean
* Consolidate version information to single location
* Improve docs
