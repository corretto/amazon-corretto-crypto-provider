# AES CFB Implementation Changes

This file tracks the changes made during the implementation of AES CFB mode.

## Initial Implementation

1. Created the C++ implementation file `aes_cfb.cpp` with support for:
   - 128-bit and 256-bit keys
   - Encryption and decryption operations
   - Update and doFinal methods

2. Created the Java implementation `AesCfbSpi.java` with:
   - Support for CFB mode with NoPadding
   - IV parameter handling
   - Key validation for 128-bit and 256-bit keys

3. Updated `AmazonCorrettoCryptoProvider.java` to register the new services:
   - AES/CFB/NoPadding
   - AES_128/CFB/NoPadding
   - AES_256/CFB/NoPadding

4. Created comprehensive test suite `AesCfbTest.java` with:
   - Basic encryption/decryption tests
   - Tests with update method
   - Tests with ByteBuffer
   - Tests with various input sizes
   - Compatibility tests with SunJCE
   - Known Answer Tests (KATs) from NIST SP 800-38A
   - Tests for invalid parameters

5. Added benchmark `AesCfbOneShot.java` to measure performance:
   - Supports both 128-bit and 256-bit keys
   - Tests various data sizes
   - Compares with SunJCE implementation