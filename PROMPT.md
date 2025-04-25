# Assignment

Hello, today we're going to implement a new block cipher mode for AES called
AES CFB. The internal details of CFB don't really matter, from the
implementor's perspective it's mostly like the other modes.

You do not need to implement any block cipher padding.

For each significant step you achieve in your implementation, please make a
commit locally and append a summary notes to a local file called CHANGES.md

# Related Work

You can find more information on AES CFB here:

https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

You can find other example commits of adding block cipher modes for AES below:

https://github.com/corretto/amazon-corretto-crypto-provider/commit/2b6d0f2b0f628021496c89ee064565e810543d29
https://github.com/corretto/amazon-corretto-crypto-provider/commit/adccfb74b84bf40ec396063606187ed55a1b2ed1
https://github.com/corretto/amazon-corretto-crypto-provider/commit/ee2fa5507fc97ec0080dc18d0d783ff1a65ea85e


# Implementation Guidance

Perform your development work on a new branch: `aes-cfb-implementation-attempt-03`

As with the other block cipher modes, you should use AWS-LC's `EVP_CIPHER` API.

You'll need to create a new `csrc/aes_cfb.cpp` file for your native JNI code
and add it in the appropriate place to `CMakeLists.txt`.

You'll also need to register the new services in
AmazonCorrettoCryptoProvider.java, something like:

```
addService("Cipher", "AES/CFB/NoPadding", "AesXtsSpi", false);
addService("Cipher", "AES_128/CFB/NoPadding", "AesXtsSpi", false);
addService("Cipher", "AES_256/CFB/NoPadding", "AesXtsSpi", false);
```

You should call your new test file `AesCfbTest.java` and you can run it with:

```
./gradlew cmake_clean singleTest -DSINGLE_TEST=com.amazon.corretto.crypto.provider.test.AesCfbTest
```

Before your test is written, you can check whether your code compiles with:

```
./gradlew cmake_clean build
```

# Requirements

Your implementation must satisfy all of the below requirements:

1. Support both 128-bit and 256-bit keys
2. Extensive unit testing of the cipher implementation
3. Add a benchmark similar to `AesGcmOneShot.java` in the `benchmarks/` folder
4. Extract some Known Answer Tests (KATs) from the test vectors in NIST SP
   800-30A and add the KATs to your test file
5. Add compatibility tests for SunJCE (encrypt with SunJCE, decrypt with ACCP)
6. All tests pass locally per the `singleTest` command above
