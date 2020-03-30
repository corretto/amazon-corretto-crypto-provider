// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assumeMinimumVersion;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyConstruct;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyInvoke_int;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import org.junit.Assume;
import org.junit.Test;

import com.amazon.corretto.crypto.provider.ExtraCheck;

public class RsaCipherTest {
    private static final String OAEP_PADDING = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
    private static final String PKCS1_PADDING = "RSA/ECB/Pkcs1Padding";
    private static final String NO_PADDING = "RSA/ECB/NoPadding";
    private static final AmazonCorrettoCryptoProvider NATIVE_PROVIDER = AmazonCorrettoCryptoProvider.INSTANCE;
    private static final KeyPairGenerator KEY_GEN;
    private static final KeyFactory KEY_FACTORY;
    private static final KeyPair PAIR_1024;
    private static final KeyPair PAIR_2048;
    private static final KeyPair PAIR_4096;
    private static final KeyPair PAIR_512;

    static {
        try {
            KEY_FACTORY = KeyFactory.getInstance("RSA");
            KEY_GEN = KeyPairGenerator.getInstance("RSA");
            KEY_GEN.initialize(1024);
            PAIR_1024 = KEY_GEN.generateKeyPair();
            KEY_GEN.initialize(2048);
            PAIR_2048 = KEY_GEN.generateKeyPair();
            KEY_GEN.initialize(4096);
            PAIR_4096 = KEY_GEN.generateKeyPair();
            KEY_GEN.initialize(512);
            PAIR_512 = KEY_GEN.generateKeyPair();
        } catch (final GeneralSecurityException ex) {
            throw new AssertionError(ex);
        }
    }

    private static byte[] getPlaintext(final int size) {
        final byte[] result = new byte[size];
        Arrays.fill(result, (byte) 0x55);
        return result;
    }

    @Test
    public void testOffsetPlaintext() throws Exception {
        final byte[] plaintext = new byte[128];
        ThreadLocalRandom.current().nextBytes(plaintext);

        Cipher cipher = Cipher.getInstance(OAEP_PADDING, NATIVE_PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, PAIR_2048.getPublic());
        byte[] ciphertext = cipher.doFinal(plaintext, 1, plaintext.length - 1);

        cipher.init(Cipher.DECRYPT_MODE, PAIR_2048.getPrivate());

        byte[] result = new byte[cipher.getOutputSize(ciphertext.length) + 2];
        int resultLen = cipher.doFinal(ciphertext, 0, ciphertext.length, result, 2);

        assertArrayEquals(Arrays.copyOfRange(plaintext, 1, plaintext.length),
                          Arrays.copyOfRange(result, 2, 2 + resultLen));
    }

    @Test
    public void testOffsetCiphertext() throws Exception {
        final byte[] plaintext = new byte[128];
        ThreadLocalRandom.current().nextBytes(plaintext);

        Cipher cipher = Cipher.getInstance(OAEP_PADDING, NATIVE_PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, PAIR_2048.getPublic());
        byte[] ciphertext = new byte[cipher.getOutputSize(plaintext.length) + 2];
        int ciphertextLen = cipher.doFinal(plaintext, 0, plaintext.length, ciphertext, 1);

        // Shift the ciphertext over before reading
        System.arraycopy(ciphertext, 1, ciphertext, 2, ciphertext.length - 2);

        cipher.init(Cipher.DECRYPT_MODE, PAIR_2048.getPrivate());

        byte[] result = cipher.doFinal(ciphertext, 2, ciphertextLen);

        assertArrayEquals(plaintext, result);
    }

    @Test
    public void native2jceNoPadding1024() throws GeneralSecurityException {
        testNative2Jce(NO_PADDING, 1024);
    }

    @Test
    public void jce2nativeNoPadding1024() throws GeneralSecurityException {
        testJce2Native(NO_PADDING, 1024);
    }

    @Test
    public void noPaddingSizes() throws GeneralSecurityException {
        final Cipher nativeEncrypt = Cipher.getInstance(NO_PADDING, NATIVE_PROVIDER);
        nativeEncrypt.init(Cipher.ENCRYPT_MODE, PAIR_1024.getPublic());

        byte[] plaintext = getPlaintext(1024 / 8 + 1);
        try {
            nativeEncrypt.doFinal(plaintext);
            fail("Expected bad padding exception");
        } catch (final BadPaddingException ex) {
            // expected
        }

        plaintext = new byte[1024 / 8];
        Arrays.fill(plaintext, (byte) 0xff);
        try {
            nativeEncrypt.doFinal(plaintext);
            fail("Expected bad padding exception");
        } catch (final BadPaddingException ex) {
            // expected
        }

        nativeEncrypt.init(Cipher.ENCRYPT_MODE, PAIR_2048.getPublic());

        plaintext = getPlaintext(2048 / 8 + 1);
        try {
            nativeEncrypt.doFinal(plaintext);
            fail("Expected bad padding exception");
        } catch (final BadPaddingException ex) {
            // expected
        }

        plaintext = new byte[2048 / 8];
        Arrays.fill(plaintext, (byte) 0xff);
        try {
            nativeEncrypt.doFinal(plaintext);
            fail("Expected bad padding exception");
        } catch (final BadPaddingException ex) {
            // expected
        }

        nativeEncrypt.init(Cipher.ENCRYPT_MODE, PAIR_4096.getPublic());

        plaintext = getPlaintext(4096 / 8 + 1);
        try {
            nativeEncrypt.doFinal(plaintext);
            fail("Expected bad padding exception");
        } catch (final BadPaddingException ex) {
            // expected
        }

        plaintext = new byte[4096 / 8];
        Arrays.fill(plaintext, (byte) 0xff);
        try {
            nativeEncrypt.doFinal(plaintext);
            fail("Expected bad padding exception");
        } catch (final BadPaddingException ex) {
            // expected
        }
    }

    @Test
    public void noPaddingShortPlaintexts() throws GeneralSecurityException {
      // We actually expect short plaintexts to be left zero padded.
      // This is acceptable because RSA just handles numbers internally
      // and adding zero-bytes to the left doesn't change the values.

      final Cipher nativeEncrypt = Cipher.getInstance(NO_PADDING, NATIVE_PROVIDER);
      final Cipher nativeDecrypt = Cipher.getInstance(NO_PADDING, NATIVE_PROVIDER);
      nativeEncrypt.init(Cipher.ENCRYPT_MODE, PAIR_1024.getPublic());
      nativeDecrypt.init(Cipher.DECRYPT_MODE, PAIR_1024.getPrivate());

      byte[] plaintext = getPlaintext(1024 / 8 - 1);
      byte[] ciphertext = nativeEncrypt.doFinal(plaintext);
      byte[] decrypted = nativeDecrypt.doFinal(ciphertext);
      assertArrayEquals(trimLeftZeros(plaintext), trimLeftZeros(decrypted));

      plaintext = getPlaintext(1024 / 8 - 10);
      ciphertext = nativeEncrypt.doFinal(plaintext);
      decrypted = nativeDecrypt.doFinal(ciphertext);
      assertArrayEquals(trimLeftZeros(plaintext), trimLeftZeros(decrypted));

      nativeEncrypt.init(Cipher.ENCRYPT_MODE, PAIR_2048.getPublic());
      nativeDecrypt.init(Cipher.DECRYPT_MODE, PAIR_2048.getPrivate());

      plaintext = getPlaintext(2048 / 8 - 1);
      ciphertext = nativeEncrypt.doFinal(plaintext);
      decrypted = nativeDecrypt.doFinal(ciphertext);
      assertArrayEquals(trimLeftZeros(plaintext), trimLeftZeros(decrypted));

      plaintext = getPlaintext(2048 / 8 - 10);
      ciphertext = nativeEncrypt.doFinal(plaintext);
      decrypted = nativeDecrypt.doFinal(ciphertext);
      assertArrayEquals(trimLeftZeros(plaintext), trimLeftZeros(decrypted));

      nativeEncrypt.init(Cipher.ENCRYPT_MODE, PAIR_4096.getPublic());
      nativeDecrypt.init(Cipher.DECRYPT_MODE, PAIR_4096.getPrivate());

      plaintext = getPlaintext(4096 / 8 - 1);
      ciphertext = nativeEncrypt.doFinal(plaintext);
      decrypted = nativeDecrypt.doFinal(ciphertext);
      assertArrayEquals(trimLeftZeros(plaintext), trimLeftZeros(decrypted));

      plaintext = getPlaintext(4096 / 8 - 10);
      ciphertext = nativeEncrypt.doFinal(plaintext);
      decrypted = nativeDecrypt.doFinal(ciphertext);
      assertArrayEquals(trimLeftZeros(plaintext), trimLeftZeros(decrypted));
    }

    private byte[] trimLeftZeros(byte[] array) {
      int offset = 0;
      while (offset < array.length && array[offset] == 0) {
          offset++;
      }
      if (offset == 0) {
          return array;
      } else if (offset == array.length) {
          return new byte[0];
      } else {
          return Arrays.copyOfRange(array, offset, array.length);
      }
    }

    @Test
    public void native2jceNoPadding2048() throws GeneralSecurityException {
        testNative2Jce(NO_PADDING, 2048);
    }

    @Test
    public void jce2nativeNoPadding2048() throws GeneralSecurityException {
        testJce2Native(NO_PADDING, 2048);
    }

    @Test
    public void native2jceNoPadding4096() throws GeneralSecurityException {
        testNative2Jce(NO_PADDING, 4096);
    }

    @Test
    public void jce2nativeNoPadding4096() throws GeneralSecurityException {
        testJce2Native(NO_PADDING, 4096);
    }

    @Test
    public void native2jcePkcs1Padding1024() throws GeneralSecurityException {
        testNative2Jce(PKCS1_PADDING, 1024);
    }

    @Test
    public void jce2nativePkcs1Padding1024() throws GeneralSecurityException {
        testJce2Native(PKCS1_PADDING, 1024);
    }

    @Test
    public void native2JcePkcs1Padding2048ReversedKeys() throws GeneralSecurityException {
        assumeMinimumVersion("1.0.1", NATIVE_PROVIDER);
        final Cipher nativeC = Cipher.getInstance(PKCS1_PADDING, NATIVE_PROVIDER);
        final Cipher jceC = Cipher.getInstance(PKCS1_PADDING);
        final byte[] plaintext = getPlaintext(512 / 8);

        nativeC.init(Cipher.ENCRYPT_MODE, PAIR_2048.getPrivate());
        final byte[] ciphertext = nativeC.doFinal(plaintext);

        jceC.init(Cipher.DECRYPT_MODE, PAIR_2048.getPublic());
        assertArrayEquals(plaintext, jceC.doFinal(ciphertext));
    }

    @Test
    public void jce2NativePkcs1Padding2048ReversedKeys() throws GeneralSecurityException {
        assumeMinimumVersion("1.0.1", NATIVE_PROVIDER);
        final Cipher nativeC = Cipher.getInstance(PKCS1_PADDING, NATIVE_PROVIDER);
        final Cipher jceC = Cipher.getInstance(PKCS1_PADDING);
        final byte[] plaintext = getPlaintext(512 / 8);

        jceC.init(Cipher.ENCRYPT_MODE, PAIR_2048.getPrivate());
        final byte[] ciphertext = jceC.doFinal(plaintext);

        nativeC.init(Cipher.DECRYPT_MODE, PAIR_2048.getPublic());
        assertArrayEquals(plaintext, nativeC.doFinal(ciphertext));
    }

    @Test
    public void native2JceNoPadding2048ReversedKeys() throws GeneralSecurityException {
        assumeMinimumVersion("1.0.1", NATIVE_PROVIDER);
        final Cipher nativeC = Cipher.getInstance(NO_PADDING, NATIVE_PROVIDER);
        final Cipher jceC = Cipher.getInstance(NO_PADDING);
        final byte[] plaintext = getPlaintext(2048 / 8);;

        nativeC.init(Cipher.ENCRYPT_MODE, PAIR_2048.getPrivate());
        final byte[] ciphertext = nativeC.doFinal(plaintext);

        jceC.init(Cipher.DECRYPT_MODE, PAIR_2048.getPublic());
        assertArrayEquals(plaintext, jceC.doFinal(ciphertext));
    }

    @Test
    public void jce2NativeNoPadding2048ReversedKeys() throws GeneralSecurityException {
        assumeMinimumVersion("1.0.1", NATIVE_PROVIDER);
        final Cipher nativeC = Cipher.getInstance(NO_PADDING, NATIVE_PROVIDER);
        final Cipher jceC = Cipher.getInstance(NO_PADDING);
        final byte[] plaintext = getPlaintext(2048 / 8);;

        jceC.init(Cipher.ENCRYPT_MODE, PAIR_2048.getPrivate());
        final byte[] ciphertext = jceC.doFinal(plaintext);

        nativeC.init(Cipher.DECRYPT_MODE, PAIR_2048.getPublic());
        assertArrayEquals(plaintext, nativeC.doFinal(ciphertext));
    }

    @Test
    public void Pkcs1PaddingSizes() throws GeneralSecurityException {
        final Cipher nativeC = Cipher.getInstance(PKCS1_PADDING, NATIVE_PROVIDER);
        nativeC.init(Cipher.ENCRYPT_MODE, PAIR_1024.getPublic());

        byte[] plaintext = getPlaintext(1024 / 8 - 10);
        try {
            nativeC.doFinal(plaintext);
            fail("Expected bad padding exception");
        } catch (final BadPaddingException ex) {
            // expected
        }

        nativeC.init(Cipher.ENCRYPT_MODE, PAIR_2048.getPublic());

        plaintext = getPlaintext(2048 / 8 - 10);
        try {
            nativeC.doFinal(plaintext);
            fail("Expected bad padding exception");
        } catch (final BadPaddingException ex) {
            // expected
        }

        nativeC.init(Cipher.ENCRYPT_MODE, PAIR_4096.getPublic());

        plaintext = getPlaintext(4096 / 8 - 10);
        try {
            nativeC.doFinal(plaintext);
            fail("Expected bad padding exception");
        } catch (final BadPaddingException ex) {
            // expected
        }
    }

    @Test
    public void native2jcePkcs1Padding2048() throws GeneralSecurityException {
        testNative2Jce(PKCS1_PADDING, 2048);
    }

    @Test
    public void jce2nativePkcs1Padding2048() throws GeneralSecurityException {
        testJce2Native(PKCS1_PADDING, 2048);
    }

    @Test
    public void native2jcePkcs1Padding4096() throws GeneralSecurityException {
        testNative2Jce(PKCS1_PADDING, 4096);
    }

    @Test
    public void jce2nativePkcs1Padding4096() throws GeneralSecurityException {
        testJce2Native(PKCS1_PADDING, 4096);
    }

    @Test
    public void native2jceOaepSha1Padding1024() throws GeneralSecurityException {
        testNative2Jce(OAEP_PADDING, 1024);
    }

    @Test
    public void jce2nativeOaepSha1Padding1024() throws GeneralSecurityException {
        testJce2Native(OAEP_PADDING, 1024);
    }

    @Test
    public void OaepSha1PaddingSizes() throws GeneralSecurityException {
        final Cipher nativeC = Cipher.getInstance(OAEP_PADDING, NATIVE_PROVIDER);
        nativeC.init(Cipher.ENCRYPT_MODE, PAIR_1024.getPublic());

        byte[] plaintext = getPlaintext(1024 / 8 - 41);
        try {
            nativeC.doFinal(plaintext);
            fail("Expected bad padding exception");
        } catch (final BadPaddingException ex) {
            // expected
        }

        nativeC.init(Cipher.ENCRYPT_MODE, PAIR_2048.getPublic());

        plaintext = getPlaintext(2048 / 8 - 41);
        try {
            nativeC.doFinal(plaintext);
            fail("Expected bad padding exception");
        } catch (final BadPaddingException ex) {
            // expected
        }

        nativeC.init(Cipher.ENCRYPT_MODE, PAIR_4096.getPublic());

        plaintext = getPlaintext(4096 / 8 - 41);
        try {
            nativeC.doFinal(plaintext);
            fail("Expected bad padding exception");
        } catch (final BadPaddingException ex) {
            // expected
        }
    }

    @Test
    public void native2jceOaepSha1Padding2048() throws GeneralSecurityException {
        testNative2Jce(OAEP_PADDING, 2048);
    }

    @Test
    public void jce2nativeOaepSha1Padding2048() throws GeneralSecurityException {
        testJce2Native(OAEP_PADDING, 2048);
    }

    @Test
    public void native2jceOaepSha1Padding4096() throws GeneralSecurityException {
        testNative2Jce(OAEP_PADDING, 4096);
    }

    @Test
    public void jce2nativeOaepSha1Padding4096() throws GeneralSecurityException {
        testJce2Native(OAEP_PADDING, 4096);
    }

    @Test
    public void native2jceNoPadding1024_parts() throws GeneralSecurityException {
        final Cipher jceC = Cipher.getInstance(NO_PADDING);
        final Cipher nativeC = Cipher.getInstance(NO_PADDING, NATIVE_PROVIDER);

        final byte[] plaintext = getPlaintext(1024 / 8);
        nativeC.init(Cipher.ENCRYPT_MODE, PAIR_1024.getPublic());
        jceC.init(Cipher.DECRYPT_MODE, PAIR_1024.getPrivate());

        nativeC.update(plaintext, 0, 64);
        nativeC.update(plaintext, 64, 64);
        final byte[] ciphertext = nativeC.doFinal();
        final byte[] decrypted = jceC.doFinal(ciphertext);
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    public void native2jceNoPadding1024_parts2() throws GeneralSecurityException {
        final Cipher jceC = Cipher.getInstance(NO_PADDING);
        final Cipher nativeC = Cipher.getInstance(NO_PADDING, NATIVE_PROVIDER);

        final byte[] plaintext = getPlaintext(1024 / 8);
        nativeC.init(Cipher.ENCRYPT_MODE, PAIR_1024.getPublic());
        jceC.init(Cipher.DECRYPT_MODE, PAIR_1024.getPrivate());

        nativeC.update(plaintext, 0, 64);
        nativeC.update(plaintext, 64, 63);
        final byte[] ciphertext = nativeC.doFinal(plaintext, plaintext.length - 1, 1);
        final byte[] decrypted = jceC.doFinal(ciphertext);
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    public void noCrt() throws GeneralSecurityException {
        // Strip out the CRT factors
        final RSAPrivateKey prvKey = (RSAPrivateKey) PAIR_1024.getPrivate();
        final PrivateKey strippedKey = KEY_FACTORY.generatePrivate(
                new RSAPrivateKeySpec(prvKey.getModulus(), prvKey.getPrivateExponent()));

        final Cipher enc = Cipher.getInstance(PKCS1_PADDING, NATIVE_PROVIDER);
        final Cipher dec = Cipher.getInstance(PKCS1_PADDING, NATIVE_PROVIDER);

        final byte[] plaintext = getPlaintext(1024 / 8 - 11);
        enc.init(Cipher.ENCRYPT_MODE, PAIR_1024.getPublic());
        dec.init(Cipher.DECRYPT_MODE, strippedKey);

        final byte[] ciphertext = enc.doFinal(plaintext);
        final byte[] decrypted = dec.doFinal(ciphertext);
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    public void badCrt() throws GeneralSecurityException {
        // Corrupt out the CRT factors
        final RSAPrivateCrtKeySpec goodSpec = KEY_FACTORY.getKeySpec(PAIR_1024.getPrivate(),
                RSAPrivateCrtKeySpec.class);
        final RSAPrivateCrtKeySpec badSpec = new RSAPrivateCrtKeySpec(goodSpec.getModulus(),
                goodSpec.getPublicExponent(), goodSpec.getPrivateExponent(), goodSpec.getPrimeP(),
                goodSpec.getPrimeQ(), goodSpec.getPrimeP(),
                goodSpec.getPrimeExponentQ().add(BigInteger.ONE),
                goodSpec.getCrtCoefficient());
        final PrivateKey privateKey = KEY_FACTORY.generatePrivate(badSpec);

        final Cipher enc = Cipher.getInstance(PKCS1_PADDING, NATIVE_PROVIDER);
        final Cipher dec = Cipher.getInstance(PKCS1_PADDING, NATIVE_PROVIDER);
        final AmazonCorrettoCryptoProvider prov = (AmazonCorrettoCryptoProvider) dec.getProvider();
        Assume.assumeTrue(prov.hasExtraCheck(ExtraCheck.PRIVATE_KEY_CONSISTENCY));

        final byte[] plaintext = getPlaintext(1024 / 8 - 11);
        enc.init(Cipher.ENCRYPT_MODE, PAIR_1024.getPublic());
        dec.init(Cipher.DECRYPT_MODE, privateKey);

        final byte[] ciphertext = enc.doFinal(plaintext);

        TestUtil.assertThrows(GeneralSecurityException.class, () -> dec.doFinal(ciphertext));
    }

    @Test
    public void smallOutputBuffer() throws GeneralSecurityException {
        final Cipher enc = Cipher.getInstance(OAEP_PADDING, NATIVE_PROVIDER);
        final Cipher dec = Cipher.getInstance(OAEP_PADDING, NATIVE_PROVIDER);

        final byte[] plaintext = getPlaintext((2048 / 8) - 42);
        enc.init(Cipher.ENCRYPT_MODE, PAIR_2048.getPublic());
        dec.init(Cipher.DECRYPT_MODE, PAIR_2048.getPrivate());

        final byte[] output = new byte[(2048 / 8) - 1];
        try {
            enc.doFinal(plaintext, 0, plaintext.length, output, 0);
            fail("Expected ShortBufferException on Encrypt");
        } catch (final ShortBufferException ex) {
            // Expected
        }
        final byte[] ciphertext = enc.doFinal(plaintext);
        try {
            dec.doFinal(ciphertext, 0, ciphertext.length, output, 0);
            fail("Expected ShortBufferException on Decrypt");
        } catch (final ShortBufferException ex) {
            // Expected
        }
    }

    @Test(expected = IllegalStateException.class)
    public void noninitialized() throws GeneralSecurityException {
        final Cipher enc = Cipher.getInstance(OAEP_PADDING, NATIVE_PROVIDER);
        final byte[] plaintext = getPlaintext((2048 / 8) - 42);
        enc.doFinal(plaintext);
    }

    @Test
    public void native2jceOaepParams() throws GeneralSecurityException {
        final Cipher nativeC = Cipher.getInstance(OAEP_PADDING, NATIVE_PROVIDER);
        final AlgorithmParameters params = nativeC.getParameters();
        assertNotNull(params);
        assertEquals("OAEP", params.getAlgorithm());
        final Cipher jceC = Cipher.getInstance(OAEP_PADDING);
        nativeC.init(Cipher.ENCRYPT_MODE, PAIR_2048.getPublic(), params);
        jceC.init(Cipher.DECRYPT_MODE, PAIR_2048.getPrivate(), params);

        final byte[] plaintext = getPlaintext(2048 / 8 - 42);

        final byte[] ciphertext = nativeC.doFinal(plaintext);
        final byte[] decrypted = jceC.doFinal(ciphertext);
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    public void pkcs1WrapAes() throws GeneralSecurityException {
        final byte[] rawKey = TestUtil.getRandomBytes(32);
        final SecretKeySpec original = new SecretKeySpec(rawKey, "AES");
        final Cipher wrap = Cipher.getInstance(PKCS1_PADDING, NATIVE_PROVIDER);
        final Cipher unwrap = Cipher.getInstance(PKCS1_PADDING, NATIVE_PROVIDER);
        wrap.init(Cipher.WRAP_MODE, PAIR_4096.getPublic());
        unwrap.init(Cipher.UNWRAP_MODE, PAIR_4096.getPrivate());

        final SecretKey unwrapped = (SecretKey) unwrap.unwrap(wrap.wrap(original), "AES", Cipher.SECRET_KEY);
        assertEquals(original.getAlgorithm(), unwrapped.getAlgorithm());
        assertArrayEquals(original.getEncoded(), unwrapped.getEncoded());
    }

    @Test
    public void jce2nativePkcs1WrapAes() throws GeneralSecurityException {
        final byte[] rawKey = TestUtil.getRandomBytes(32);
        final SecretKeySpec original = new SecretKeySpec(rawKey, "AES");
        final Cipher jceC = Cipher.getInstance(PKCS1_PADDING);
        final Cipher nativeC = Cipher.getInstance(PKCS1_PADDING, NATIVE_PROVIDER);
        jceC.init(Cipher.WRAP_MODE, PAIR_4096.getPublic());
        nativeC.init(Cipher.UNWRAP_MODE, PAIR_4096.getPrivate());

        final SecretKey unwrapped = (SecretKey) nativeC.unwrap(jceC.wrap(original), "AES", Cipher.SECRET_KEY);
        assertEquals(original.getAlgorithm(), unwrapped.getAlgorithm());
        assertArrayEquals(original.getEncoded(), unwrapped.getEncoded());
    }

    @Test
    public void native2JcePkcs1WrapAes() throws GeneralSecurityException {
        final byte[] rawKey = TestUtil.getRandomBytes(32);
        final SecretKeySpec original = new SecretKeySpec(rawKey, "AES");
        final Cipher jceC = Cipher.getInstance(PKCS1_PADDING);
        final Cipher nativeC = Cipher.getInstance(PKCS1_PADDING, NATIVE_PROVIDER);
        jceC.init(Cipher.UNWRAP_MODE, PAIR_4096.getPrivate());
        nativeC.init(Cipher.WRAP_MODE, PAIR_4096.getPublic());

        final SecretKey unwrapped = (SecretKey) jceC.unwrap(nativeC.wrap(original), "AES", Cipher.SECRET_KEY);
        assertEquals(original.getAlgorithm(), unwrapped.getAlgorithm());
        assertArrayEquals(original.getEncoded(), unwrapped.getEncoded());
    }

    @Test
    public void oaepWrapAes() throws GeneralSecurityException {
        final byte[] rawKey = TestUtil.getRandomBytes(32);
        final SecretKeySpec original = new SecretKeySpec(rawKey, "AES");
        final Cipher wrap = Cipher.getInstance(OAEP_PADDING, NATIVE_PROVIDER);
        final Cipher unwrap = Cipher.getInstance(OAEP_PADDING, NATIVE_PROVIDER);
        wrap.init(Cipher.WRAP_MODE, PAIR_4096.getPublic());
        unwrap.init(Cipher.UNWRAP_MODE, PAIR_4096.getPrivate());

        final SecretKey unwrapped = (SecretKey) unwrap.unwrap(wrap.wrap(original), "AES", Cipher.SECRET_KEY);
        assertEquals(original.getAlgorithm(), unwrapped.getAlgorithm());
        assertArrayEquals(original.getEncoded(), unwrapped.getEncoded());
    }

    @Test
    public void jce2nativeOaepWrapAes() throws GeneralSecurityException {
        final byte[] rawKey = TestUtil.getRandomBytes(32);
        final SecretKeySpec original = new SecretKeySpec(rawKey, "AES");
        final Cipher jceC = Cipher.getInstance(OAEP_PADDING);
        final Cipher nativeC = Cipher.getInstance(OAEP_PADDING, NATIVE_PROVIDER);
        jceC.init(Cipher.WRAP_MODE, PAIR_4096.getPublic());
        nativeC.init(Cipher.UNWRAP_MODE, PAIR_4096.getPrivate());

        final SecretKey unwrapped = (SecretKey) nativeC.unwrap(jceC.wrap(original), "AES", Cipher.SECRET_KEY);
        assertEquals(original.getAlgorithm(), unwrapped.getAlgorithm());
        assertArrayEquals(original.getEncoded(), unwrapped.getEncoded());
    }

    @Test
    public void native2JceOaepWrapAes() throws GeneralSecurityException {
        final byte[] rawKey = TestUtil.getRandomBytes(32);
        final SecretKeySpec original = new SecretKeySpec(rawKey, "AES");
        final Cipher jceC = Cipher.getInstance(OAEP_PADDING);
        final Cipher nativeC = Cipher.getInstance(OAEP_PADDING, NATIVE_PROVIDER);
        jceC.init(Cipher.UNWRAP_MODE, PAIR_4096.getPrivate());
        nativeC.init(Cipher.WRAP_MODE, PAIR_4096.getPublic());

        final SecretKey unwrapped = (SecretKey) jceC.unwrap(nativeC.wrap(original), "AES", Cipher.SECRET_KEY);
        assertEquals(original.getAlgorithm(), unwrapped.getAlgorithm());
        assertArrayEquals(original.getEncoded(), unwrapped.getEncoded());
    }

    @Test
    public void jce2nativePkcs1WrapRsa() throws GeneralSecurityException {
        final Cipher jceC = Cipher.getInstance(PKCS1_PADDING);
        final Cipher nativeC = Cipher.getInstance(PKCS1_PADDING, NATIVE_PROVIDER);
        wrapUnwrap(jceC, nativeC);
    }

    @Test
    public void native2JcePkcs1WrapRsa() throws GeneralSecurityException {
        final Cipher jceC = Cipher.getInstance(PKCS1_PADDING);
        final Cipher nativeC = Cipher.getInstance(PKCS1_PADDING, NATIVE_PROVIDER);
        wrapUnwrap(nativeC, jceC);
    }

    @Test
    public void jce2nativeOaepWrapRsa() throws GeneralSecurityException {
        final Cipher jceC = Cipher.getInstance(OAEP_PADDING);
        final Cipher nativeC = Cipher.getInstance(OAEP_PADDING, NATIVE_PROVIDER);
        wrapUnwrap(jceC, nativeC);
    }

    @Test
    public void native2JceOaepWrapRsa() throws GeneralSecurityException {
        final Cipher jceC = Cipher.getInstance(OAEP_PADDING);
        final Cipher nativeC = Cipher.getInstance(OAEP_PADDING, NATIVE_PROVIDER);
        wrapUnwrap(nativeC, jceC);
    }

    @Test(expected = BadPaddingException.class)
    public void badPaddingTooSmallPkcs1() throws Exception {
        final Cipher enc = Cipher.getInstance(NO_PADDING, NATIVE_PROVIDER);
        enc.init(Cipher.ENCRYPT_MODE, PAIR_2048.getPublic());
        final byte[] plaintext = new byte[512 / 8];
        plaintext[plaintext.length - 1] = 2;
        final byte[] ciphertext = enc.doFinal(plaintext);
        final Cipher dec = Cipher.getInstance(PKCS1_PADDING, NATIVE_PROVIDER);
        dec.init(Cipher.DECRYPT_MODE, PAIR_2048.getPrivate());
        dec.doFinal(ciphertext);
    }

    @Test(expected = BadPaddingException.class)
    public void badPaddingTooSmallOaep() throws Exception {
        final Cipher enc = Cipher.getInstance(NO_PADDING, NATIVE_PROVIDER);
        enc.init(Cipher.ENCRYPT_MODE, PAIR_2048.getPublic());
        final byte[] plaintext = new byte[512 / 8];
        plaintext[plaintext.length - 1] = 2;
        byte[] ciphertext = enc.doFinal(plaintext);
        final Cipher dec = Cipher.getInstance(PKCS1_PADDING, NATIVE_PROVIDER);
        dec.init(Cipher.DECRYPT_MODE, PAIR_2048.getPrivate());
        dec.doFinal(ciphertext);
    }

    @Test(expected = BadPaddingException.class)
    public void badPaddingTooBigPkcs1() throws Exception {
        final Cipher enc = Cipher.getInstance(NO_PADDING, NATIVE_PROVIDER);
        enc.init(Cipher.ENCRYPT_MODE, PAIR_2048.getPublic());
        final byte[] plaintext = new byte[2048 / 8];
        Arrays.fill(plaintext, (byte) 1);
        byte[] ciphertext = enc.doFinal(plaintext);
        final Cipher dec = Cipher.getInstance(PKCS1_PADDING, NATIVE_PROVIDER);
        dec.init(Cipher.DECRYPT_MODE, PAIR_2048.getPrivate());
        dec.doFinal(ciphertext);
    }

    @Test(expected = BadPaddingException.class)
    public void slightlyOverlargePlaintextNoPadding() throws Exception {
        final Cipher enc = Cipher.getInstance(NO_PADDING, NATIVE_PROVIDER);
        enc.init(Cipher.ENCRYPT_MODE, PAIR_2048.getPublic());
        byte[] plaintext = ((RSAPublicKey) PAIR_2048.getPublic()).getModulus().toByteArray();
        // Strip leading zero sign bit/byte if present
        if (plaintext[0] == 0) {
            plaintext = Arrays.copyOfRange(plaintext, 1, plaintext.length);
        }
        enc.doFinal(plaintext);
    }

    @Test(expected = BadPaddingException.class)
    public void slightlyOverlargePlaintextPkcs1() throws Exception {
        final Cipher enc = Cipher.getInstance(PKCS1_PADDING, NATIVE_PROVIDER);
        enc.init(Cipher.ENCRYPT_MODE, PAIR_2048.getPublic());
        byte[] plaintext = ((RSAPublicKey) PAIR_2048.getPublic()).getModulus().toByteArray();
        // Strip leading zero sign bit/byte if present
        if (plaintext[0] == 0) {
            plaintext = Arrays.copyOfRange(plaintext, 1, plaintext.length);
        }
        enc.doFinal(plaintext);
    }

    @Test(expected = BadPaddingException.class)
    public void slightlyOverlargePlaintextOaepSha1() throws Exception {
        final Cipher enc = Cipher.getInstance(OAEP_PADDING, NATIVE_PROVIDER);
        enc.init(Cipher.ENCRYPT_MODE, PAIR_2048.getPublic());
        byte[] plaintext = ((RSAPublicKey) PAIR_2048.getPublic()).getModulus().toByteArray();
        // Strip leading zero sign bit/byte if present
        if (plaintext[0] == 0) {
            plaintext = Arrays.copyOfRange(plaintext, 1, plaintext.length);
        }
        enc.doFinal(plaintext);
    }

    @Test(expected = BadPaddingException.class)
    public void slightlyOverlargeCiphertextNoPadding() throws Exception {
        final Cipher dec = Cipher.getInstance(NO_PADDING, NATIVE_PROVIDER);
        dec.init(Cipher.DECRYPT_MODE, PAIR_2048.getPrivate());
        byte[] plaintext = ((RSAPublicKey) PAIR_2048.getPublic()).getModulus().toByteArray();
        // Strip leading zero sign bit/byte if present
        if (plaintext[0] == 0) {
            plaintext = Arrays.copyOfRange(plaintext, 1, plaintext.length);
        }
        dec.doFinal(plaintext);
    }

    @Test(expected = BadPaddingException.class)
    public void slightlyOverlargeCiphertextPkcs1() throws Exception {
        final Cipher dec = Cipher.getInstance(PKCS1_PADDING, NATIVE_PROVIDER);
        dec.init(Cipher.DECRYPT_MODE, PAIR_2048.getPrivate());
        byte[] plaintext = ((RSAPublicKey) PAIR_2048.getPublic()).getModulus().toByteArray();
        // Strip leading zero sign bit/byte if present
        if (plaintext[0] == 0) {
            plaintext = Arrays.copyOfRange(plaintext, 1, plaintext.length);
        }
        dec.doFinal(plaintext);
    }

    @Test(expected = BadPaddingException.class)
    public void slightlyOverlargeCiphertextOaepSha1() throws Exception {
        final Cipher dec = Cipher.getInstance(OAEP_PADDING, NATIVE_PROVIDER);
        dec.init(Cipher.DECRYPT_MODE, PAIR_2048.getPrivate());
        byte[] plaintext = ((RSAPublicKey) PAIR_2048.getPublic()).getModulus().toByteArray();
        // Strip leading zero sign bit/byte if present
        if (plaintext[0] == 0) {
            plaintext = Arrays.copyOfRange(plaintext, 1, plaintext.length);
        }
        dec.doFinal(plaintext);
    }

    @Test
    public void engineGetKeySize() throws Throwable {
        final Object cipherSpi = sneakyConstruct("com.amazon.corretto.crypto.provider.RsaCipher$Pkcs1", NATIVE_PROVIDER);
        assertEquals(1024, sneakyInvoke_int(cipherSpi, "engineGetKeySize", PAIR_1024.getPublic()));
        assertEquals(1024, sneakyInvoke_int(cipherSpi, "engineGetKeySize", PAIR_1024.getPrivate()));
        assertEquals(2048, sneakyInvoke_int(cipherSpi, "engineGetKeySize", PAIR_2048.getPublic()));
        assertEquals(2048, sneakyInvoke_int(cipherSpi, "engineGetKeySize", PAIR_2048.getPrivate()));
        assertEquals(4096, sneakyInvoke_int(cipherSpi, "engineGetKeySize", PAIR_4096.getPublic()));
        assertEquals(4096, sneakyInvoke_int(cipherSpi, "engineGetKeySize", PAIR_4096.getPrivate()));
    }

    @Test
    public void threadStorm() throws Throwable {
        final byte[] rngSeed = TestUtil.getRandomBytes(20);
        System.out.println("RNG Seed: " + Arrays.toString(rngSeed));
        final SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");
        rng.setSeed(rngSeed);
        final int iterations = 500;
        final int threadCount = 48;

        final List<TestThread> threads = new ArrayList<>();
        for (int x = 0; x < threadCount; x++) {
            final List<KeyPair> keys = new ArrayList<KeyPair>();
            while (keys.isEmpty()) {
                if (rng.nextBoolean()) {
                    keys.add(PAIR_1024);
                }
                if (rng.nextBoolean()) {
                    keys.add(PAIR_2048);
                }
                if (rng.nextBoolean()) {
                    keys.add(PAIR_4096);
                }
            }
            threads.add(new TestThread("RsaCipherThread-" + x, rng, iterations, OAEP_PADDING, keys));
        }

        // Start the threads
        for (final TestThread t : threads) {
            t.start();
        }

        // Wait and collect the results
        final List<Throwable> results = new ArrayList<>();
        for (final TestThread t : threads) {
            t.join();
            if (t.result != null) {
                results.add(t.result);
            }
        }
        if (!results.isEmpty()) {
            final AssertionError ex = new AssertionError("Throwable while testing threads");
            for (final Throwable t : results) {
                t.printStackTrace();
                ex.addSuppressed(t);
            }
            throw ex;
        }
    }

    private void testNative2Jce(final String padding, final int keySize) throws GeneralSecurityException {
        final Cipher jceC = Cipher.getInstance(padding);
        final Cipher nativeC = Cipher.getInstance(padding, NATIVE_PROVIDER);

        testEncryptDecryptCycle(jceC, nativeC, padding, keySize);
    }

    private void testJce2Native(final String padding, final int keySize) throws GeneralSecurityException {
        final Cipher jceC = Cipher.getInstance(padding);
        final Cipher nativeC = Cipher.getInstance(padding, NATIVE_PROVIDER);

        testEncryptDecryptCycle(nativeC, jceC, padding, keySize);
    }

    private void testEncryptDecryptCycle(final Cipher encrypt, final Cipher decrypt, final String padding,
            final int keySize) throws GeneralSecurityException {
        final int paddingSize;
        switch (padding) {
            case NO_PADDING:
                paddingSize = 0;
                break;
            case PKCS1_PADDING:
                paddingSize = 11;
                break;
            case OAEP_PADDING:
                paddingSize = 42;
                break;
            default:
                throw new IllegalArgumentException("Bad padding: " + padding);
        }

        final byte[] plaintext = getPlaintext((keySize / 8) - paddingSize);

        final KeyPair pair;
        switch (keySize) {
            case 512:
                pair = PAIR_512;
                break;
            case 1024:
                pair = PAIR_1024;
                break;
            case 2048:
                pair = PAIR_2048;
                break;
            case 4096:
                pair = PAIR_4096;
                break;
            default:
                throw new IllegalArgumentException("Bad keysize: " + keySize);
        }

        encrypt.init(Cipher.ENCRYPT_MODE, pair.getPublic());
        decrypt.init(Cipher.DECRYPT_MODE, pair.getPrivate());

        final byte[] ciphertext = encrypt.doFinal(plaintext);
        final byte[] decrypted = decrypt.doFinal(ciphertext);
        assertArrayEquals(plaintext, decrypted);
    }

    private void wrapUnwrap(final Cipher wrap, final Cipher unwrap) throws InvalidKeyException,
            IllegalBlockSizeException, NoSuchAlgorithmException {
        wrap.init(Cipher.WRAP_MODE, PAIR_4096.getPublic());
        unwrap.init(Cipher.UNWRAP_MODE, PAIR_4096.getPrivate());

        byte[] wrapped = wrap.wrap(PAIR_512.getPublic());
        final PublicKey pub = (PublicKey) unwrap.unwrap(wrapped, "RSA", Cipher.PUBLIC_KEY);
        assertEquals(PAIR_512.getPublic().getAlgorithm(), pub.getAlgorithm());
        assertArrayEquals(PAIR_512.getPublic().getEncoded(), pub.getEncoded());
        wrapped = wrap.wrap(PAIR_512.getPrivate());
        final PrivateKey priv = (PrivateKey) unwrap.unwrap(wrapped, "RSA", Cipher.PRIVATE_KEY);
        assertEquals(PAIR_512.getPrivate().getAlgorithm(), priv.getAlgorithm());
        assertArrayEquals(PAIR_512.getPrivate().getEncoded(), priv.getEncoded());
    }

    private class TestThread extends Thread {
        private final SecureRandom rnd_;
        private final List<KeyPair> keys_;
        private final Cipher enc_;
        private final Cipher dec_;
        private final int iterations_;
        private final byte[] plaintext_;
        public volatile Throwable result = null;

        public TestThread(final String name, final SecureRandom rng, final int iterations, final String transformation,
                final List<KeyPair> keys) throws GeneralSecurityException {
            super(name);
            iterations_ = iterations;
            keys_ = keys;
            enc_ = Cipher.getInstance(transformation, NATIVE_PROVIDER);
            dec_ = Cipher.getInstance(transformation, NATIVE_PROVIDER);
            plaintext_ = new byte[64];
            rnd_ = SecureRandom.getInstance("SHA1PRNG");
            final byte[] seed = new byte[20];
            rng.nextBytes(seed);
            rnd_.setSeed(seed);
            rnd_.nextBytes(plaintext_);
        }

        @Override
        public void run() {
            for (int x = 0; x < iterations_; x++) {
                try {
                    final KeyPair pair = keys_.get(rnd_.nextInt(keys_.size()));
                    enc_.init(Cipher.ENCRYPT_MODE, pair.getPublic());
                    dec_.init(Cipher.DECRYPT_MODE, pair.getPrivate());
                    assertArrayEquals(plaintext_, dec_.doFinal(enc_.doFinal(plaintext_)));
                } catch (final Throwable ex) {
                    result = ex;
                    return;
                }
            }
        }
    }
}
