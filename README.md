# Amazon Corretto Crypto Provider
The Amazon Corretto Crypto Provider (ACCP) is a collection of high-performance cryptographic implementations exposed via the standard [JCA/JCE](https://docs.oracle.com/en/java/javase/11/security/java-cryptography-architecture-jca-reference-guide.html) interfaces. This means that it can be used as a drop in replacement for many different Java applications. Currently algorithms are primarily backed by OpenSSL's implementations but this may change in the future.

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
* SHA224withECDSA
* SHA256withECDSA
* SHA384withECDSA
* SHA512withECDSA

KeyPairGenerator algorithms:
* EC
* RSA

KeyAgreement:
* DH
* DiffieHellman (same as DH)
* ECDH

SecureRandom algorithms:
* NIST800-90A/AES-CTR-256 (Used as the default and only enabled if your CPU supports RDRAND)


# Compatibility
This library is compatible with:
* OpenJDK 8 or newer (This include [Amazon Corretto](https://aws.amazon.com/corretto/))
* Linux x86_64

If ACCP is used/installed on a system it does not support, it will disable itself and the JVM will behave as if ACCP weren't installed at all.

## Future Compatibility (Soon)
* OracleJDK 8 or newer
* ARM64

# Installation
Currently we only support manual installation. In the future much of this will be automated by integration with Maven.

## Acquiring the provider
You can either download the provider from our official [releases](https://github.com/corretto/amazon-corretto-crypto-provider/releases) or by building it yourself.

### Building
Building this provider requires a 64 bit Linux build system with the following prerequisites installed:
* OpenJDK 10 or newer
* [cmake](https://cmake.org/) 3.8 or newer
* C++ build chain
* [lcov](http://ltp.sourceforge.net/coverage/lcov.php) for coverage metrics
* [dieharder](http://webhome.phy.duke.edu/~rgb/General/dieharder.php) for entropy tests

1. Download the repository through a git clone
2. Run `./gradlew release`
3. The resulting jar is in `build/lib`

### All targets
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

## Add the provider to your classpath
This is done in a application/system specific manner

## Install the provider in Java
There are several ways to install the ACCP as the highest priority provider in Java.

### Code
Run the following method early in program start up: `com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider.install()`

### Via Security Properties
Add the following Java property to your programs command line: `-Djava.security.properties=/path/to/amazon-corretto-crypto-provider.security` where amazon-corretto-crypto-provider.security is [downloaded from](https://github.com/corretto/amazon-corretto-crypto-provider/blob/master/etc/amazon-corretto-crypto-provider.security) our repository.

### Modify the JVM settings
Modify the `java.security` file provided by your JVM so that the highest priority provider is the Amazon Corretto Crypto Provider. Look at [amazon-corretto-crypto-provider.security](https://github.com/corretto/amazon-corretto-crypto-provider/blob/master/etc/amazon-corretto-crypto-provider.security) for an example of what this change will look like.

### Verification (Optional)
If you want to check to verify that ACCP is properly working on your system, you can do any of the following:
1. Verify that the highest priority provider actually is ACCP:
```
if (Cipher.getInstance("AES/GCM/NoPadding").getProvider().getName().equals(AmazonCorrettoCryptoProvider.PROVIDER_NAME)) {
	// Successfully installed
}
```
2. Ask ACCP about its health
```
if (AmazonCorrettoCryptoProvider.INSTANCE.getLoadingError() == null && AmazonCorrettoCryptoProvider.INSTANCE.runSelfTests().equals(SelfTestState.PASSED)) {
	// Successfully installed
}
```
3. Assert that ACCP is healthy and throw a `RuntimeCryptoException` if it isn't.
```
AmazonCorrettoCryptoProvider.INSTANCE.assertHealthy();
```

# License
This library is licensed under the Apache 2.0 License. 
