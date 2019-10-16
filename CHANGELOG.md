# Changelog

## 1.2.0

### Improvements
* Now uses [OpenSSL 1.1.1.d](https://www.openssl.org/source/openssl-1.1.1d.tar.gz)

### Maintenance
* Add prefix to test output lines indicating if suite will fail.
* Now colored output from tests can be disabled by setting the environment variable `ACCP_TEST_COLOR` to `false`

## 1.1.1

### Patches
* `amazon-corretto-crypto-provider.security` updated to work on both JDK8 and JDK9+
* Improve performance of single-byte handling in message digests.

### Maintenance
* Support using a different JDK for testing via the `TEST_JAVA_HOME` JVM property
* Clarify licensing

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
