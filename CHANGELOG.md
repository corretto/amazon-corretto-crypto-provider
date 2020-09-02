# Changelog

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
