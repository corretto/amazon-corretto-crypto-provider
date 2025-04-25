// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;

@ExtendWith(TestResultLogger.class)
public class AesCfbTest {
    private static final String PROVIDER_NAME = "AmazonCorrettoCryptoProvider";
    private static final String ALGORITHM = "AES/CFB/NoPadding";
    private static final int BLOCK_SIZE = 16;
    private static final int KEY_SIZE_128 = 128;
    private static final int KEY_SIZE_256 = 256;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    @BeforeAll
    public static void setUp() {
        TestUtil.installProvider();
    }

    @Test
    public void testBasicEncryptDecrypt() throws Exception {
        final byte[] plaintext = "This is a test message for AES CFB mode".getBytes();
        final SecretKey key = generateKey(KEY_SIZE_128);
        final byte[] iv = new byte[BLOCK_SIZE];
        SECURE_RANDOM.nextBytes(iv);
        final IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Encrypt
        final Cipher encryptCipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
        encryptCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        final byte[] ciphertext = encryptCipher.doFinal(plaintext);

        // Decrypt
        final Cipher decryptCipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
        decryptCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        final byte[] decrypted = decryptCipher.doFinal(ciphertext);

        assertArrayEquals(plaintext, decrypted, "Decrypted text should match original plaintext");
    }

    @Test
    public void testEncryptDecryptWithUpdate() throws Exception {
        final byte[] plaintext = new byte[100];
        SECURE_RANDOM.nextBytes(plaintext);
        final SecretKey key = generateKey(KEY_SIZE_256);
        final byte[] iv = new byte[BLOCK_SIZE];
        SECURE_RANDOM.nextBytes(iv);
        final IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Encrypt
        final Cipher encryptCipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
        encryptCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        final byte[] firstPart = encryptCipher.update(plaintext, 0, 50);
        final byte[] secondPart = encryptCipher.doFinal(plaintext, 50, 50);
        final byte[] ciphertext = new byte[firstPart.length + secondPart.length];
        System.arraycopy(firstPart, 0, ciphertext, 0, firstPart.length);
        System.arraycopy(secondPart, 0, ciphertext, firstPart.length, secondPart.length);

        // Decrypt
        final Cipher decryptCipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
        decryptCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        final byte[] firstDecrypted = decryptCipher.update(ciphertext, 0, 50);
        final byte[] secondDecrypted = decryptCipher.doFinal(ciphertext, 50, ciphertext.length - 50);
        final byte[] decrypted = new byte[firstDecrypted.length + secondDecrypted.length];
        System.arraycopy(firstDecrypted, 0, decrypted, 0, firstDecrypted.length);
        System.arraycopy(secondDecrypted, 0, decrypted, firstDecrypted.length, secondDecrypted.length);

        assertArrayEquals(plaintext, decrypted, "Decrypted text should match original plaintext");
    }

    @Test
    public void testEncryptDecryptWithByteBuffer() throws Exception {
        final byte[] plaintext = new byte[100];
        SECURE_RANDOM.nextBytes(plaintext);
        final SecretKey key = generateKey(KEY_SIZE_128);
        final byte[] iv = new byte[BLOCK_SIZE];
        SECURE_RANDOM.nextBytes(iv);
        final IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Encrypt
        final Cipher encryptCipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
        encryptCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        final ByteBuffer plaintextBuffer = ByteBuffer.wrap(plaintext);
        final ByteBuffer ciphertextBuffer = ByteBuffer.allocate(plaintext.length);
        encryptCipher.doFinal(plaintextBuffer, ciphertextBuffer);
        ciphertextBuffer.flip();
        final byte[] ciphertext = new byte[ciphertextBuffer.remaining()];
        ciphertextBuffer.get(ciphertext);

        // Decrypt
        final Cipher decryptCipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
        decryptCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        final ByteBuffer decryptedBuffer = ByteBuffer.allocate(ciphertext.length);
        decryptCipher.doFinal(ByteBuffer.wrap(ciphertext), decryptedBuffer);
        decryptedBuffer.flip();
        final byte[] decrypted = new byte[decryptedBuffer.remaining()];
        decryptedBuffer.get(decrypted);

        assertArrayEquals(plaintext, decrypted, "Decrypted text should match original plaintext");
    }

    @Test
    public void testVariousInputSizes() throws Exception {
        final SecretKey key = generateKey(KEY_SIZE_256);
        final byte[] iv = new byte[BLOCK_SIZE];
        SECURE_RANDOM.nextBytes(iv);
        final IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Test different input sizes
        for (int size : new int[] {1, 15, 16, 17, 32, 33, 63, 64, 65, 127, 128, 129}) {
            final byte[] plaintext = new byte[size];
            SECURE_RANDOM.nextBytes(plaintext);

            // Encrypt
            final Cipher encryptCipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
            encryptCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            final byte[] ciphertext = encryptCipher.doFinal(plaintext);

            // Decrypt
            final Cipher decryptCipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
            decryptCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
            final byte[] decrypted = decryptCipher.doFinal(ciphertext);

            assertArrayEquals(plaintext, decrypted, "Decrypted text should match original plaintext for size " + size);
        }
    }

    @Test
    public void testCompatibilityWithSunJCE() throws Exception {
        // Skip if SunJCE doesn't support AES/CFB/NoPadding
        try {
            Cipher.getInstance("AES/CFB/NoPadding", "SunJCE");
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
            System.out.println("SunJCE does not support AES/CFB/NoPadding, skipping compatibility test");
            return;
        }

        final byte[] plaintext = "This is a test message for AES CFB mode compatibility".getBytes();
        final SecretKey key = generateKey(KEY_SIZE_128);
        final byte[] iv = new byte[BLOCK_SIZE];
        SECURE_RANDOM.nextBytes(iv);
        final IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Encrypt with SunJCE
        final Cipher sunEncryptCipher = Cipher.getInstance("AES/CFB/NoPadding", "SunJCE");
        sunEncryptCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        final byte[] sunCiphertext = sunEncryptCipher.doFinal(plaintext);

        // Decrypt with ACCP
        final Cipher accpDecryptCipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
        accpDecryptCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        final byte[] accpDecrypted = accpDecryptCipher.doFinal(sunCiphertext);

        assertArrayEquals(plaintext, accpDecrypted, "ACCP should be able to decrypt SunJCE ciphertext");

        // Encrypt with ACCP
        final Cipher accpEncryptCipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
        accpEncryptCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        final byte[] accpCiphertext = accpEncryptCipher.doFinal(plaintext);

        // Decrypt with SunJCE
        final Cipher sunDecryptCipher = Cipher.getInstance("AES/CFB/NoPadding", "SunJCE");
        sunDecryptCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        final byte[] sunDecrypted = sunDecryptCipher.doFinal(accpCiphertext);

        assertArrayEquals(plaintext, sunDecrypted, "SunJCE should be able to decrypt ACCP ciphertext");
    }

    @Test
    public void testKnownAnswerVectors() throws Exception {
        // Test vectors from NIST SP 800-38A, section F.3.17 and F.3.18 (CFB128-AES256)
        final byte[] key = TestUtil.hexToBytes(
                "603deb1015ca71be2b73aef0857d7781" +
                "1f352c073b6108d72d9810a30914dff4");
        final byte[] iv = TestUtil.hexToBytes("000102030405060708090a0b0c0d0e0f");
        final byte[] plaintext = TestUtil.hexToBytes(
                "6bc1bee22e409f96e93d7e117393172a" +
                "ae2d8a571e03ac9c9eb76fac45af8e51" +
                "30c81c46a35ce411e5fbc1191a0a52ef" +
                "f69f2445df4f9b17ad2b417be66c3710");
        final byte[] expectedCiphertext = TestUtil.hexToBytes(
                "dc7e84bfda79164b7ecd8486985d3860" +
                "39ffed143b28b1c832113c6331e5407b" +
                "df10132415e54b92a13ed0a8267ae2f9" +
                "75a385741ab9cef82031623d55b1e471");

        // Test encryption
        final SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        final IvParameterSpec ivSpec = new IvParameterSpec(iv);
        final Cipher encryptCipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
        encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        final byte[] ciphertext = encryptCipher.doFinal(plaintext);
        assertArrayEquals(expectedCiphertext, ciphertext, "Encryption should match known answer vector");

        // Test decryption
        final Cipher decryptCipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
        decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        final byte[] decrypted = decryptCipher.doFinal(expectedCiphertext);
        assertArrayEquals(plaintext, decrypted, "Decryption should match known answer vector");
    }

    @Test
    public void testKnownAnswerVectors128() throws Exception {
        // Test vectors from NIST SP 800-38A, section F.3.13 and F.3.14 (CFB128-AES128)
        final byte[] key = TestUtil.hexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
        final byte[] iv = TestUtil.hexToBytes("000102030405060708090a0b0c0d0e0f");
        final byte[] plaintext = TestUtil.hexToBytes(
                "6bc1bee22e409f96e93d7e117393172a" +
                "ae2d8a571e03ac9c9eb76fac45af8e51" +
                "30c81c46a35ce411e5fbc1191a0a52ef" +
                "f69f2445df4f9b17ad2b417be66c3710");
        final byte[] expectedCiphertext = TestUtil.hexToBytes(
                "3b3fd92eb72dad20333449f8e83cfb4a" +
                "c8a64537a0b3a93fcde3cdad9f1ce58b" +
                "26751f67a3cbb140b1808cf187a4f4df" +
                "c04b05357c5d1c0eeac4c66f9ff7f2e6");

        // Test encryption
        final SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        final IvParameterSpec ivSpec = new IvParameterSpec(iv);
        final Cipher encryptCipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
        encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        final byte[] ciphertext = encryptCipher.doFinal(plaintext);
        assertArrayEquals(expectedCiphertext, ciphertext, "Encryption should match known answer vector");

        // Test decryption
        final Cipher decryptCipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
        decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        final byte[] decrypted = decryptCipher.doFinal(expectedCiphertext);
        assertArrayEquals(plaintext, decrypted, "Decryption should match known answer vector");
    }

    @Test
    public void testInvalidParameters() throws Exception {
        final SecretKey key = generateKey(KEY_SIZE_128);
        final byte[] iv = new byte[BLOCK_SIZE];
        SECURE_RANDOM.nextBytes(iv);
        final IvParameterSpec ivSpec = new IvParameterSpec(iv);
        final Cipher cipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);

        // Test invalid IV size
        final byte[] shortIv = new byte[BLOCK_SIZE - 1];
        SECURE_RANDOM.nextBytes(shortIv);
        final IvParameterSpec shortIvSpec = new IvParameterSpec(shortIv);
        assertThrows(InvalidAlgorithmParameterException.class, 
                () -> cipher.init(Cipher.ENCRYPT_MODE, key, shortIvSpec),
                "Should throw exception for invalid IV size");

        // Test invalid key size
        final byte[] invalidKey = new byte[24]; // 192 bits, not supported
        SECURE_RANDOM.nextBytes(invalidKey);
        final SecretKeySpec invalidKeySpec = new SecretKeySpec(invalidKey, "AES");
        assertThrows(InvalidKeyException.class, 
                () -> cipher.init(Cipher.ENCRYPT_MODE, invalidKeySpec, ivSpec),
                "Should throw exception for invalid key size");

        // Test invalid padding
        assertThrows(NoSuchPaddingException.class, 
                () -> Cipher.getInstance("AES/CFB/PKCS5Padding", PROVIDER_NAME),
                "Should throw exception for unsupported padding");
    }

    private SecretKey generateKey(int keySize) throws NoSuchAlgorithmException, NoSuchProviderException {
        final KeyGenerator keyGen = KeyGenerator.getInstance("AES", PROVIDER_NAME);
        keyGen.init(keySize);
        return keyGen.generateKey();
    }
}