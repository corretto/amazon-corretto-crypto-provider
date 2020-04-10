# Changelog

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
