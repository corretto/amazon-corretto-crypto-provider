// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assertArraysHexEquals;
import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyConstruct;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyInvoke;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public final class AesKeyWrapTest {
  private static final Class<?> SPI_CLASS;

  static {
    try {
      SPI_CLASS = Class.forName("com.amazon.corretto.crypto.provider.AesKeyWrapSpi");
    } catch (final ClassNotFoundException ex) {
      throw new AssertionError(ex);
    }
  }

  private static final Key NULL_KEY;

  static {
    NULL_KEY =
        new Key() {
          public String getAlgorithm() {
            return null;
          }

          public String getFormat() {
            return null;
          }

          public byte[] getEncoded() {
            return null;
          }
        };
  }

  private static final List<String> KW_CIPHER_ALIASES =
      Arrays.asList("AESWRAP", "AesWrap", "AES/KW/NoPadding");

  private static final List<Integer> AES_KEY_SIZES = Arrays.asList(16, 24, 32);

  private static final List<Integer> SECRET_SIZES =
      Arrays.asList(
          16,
          24,
          32, // AES keys
          512,
          1024,
          2048,
          4096 // RSA keys
          );

  private static final int[] IV_SIZES = {0, 8};

  private static List<Arguments> getParamsGeneric() {
    List<Arguments> args = new ArrayList<>();
    for (int ivSize : IV_SIZES) {
      for (int wrappingKeySize : AES_KEY_SIZES) {
        for (int secretSize : SECRET_SIZES) {
          args.add(Arguments.of(ivSize, wrappingKeySize, secretSize));
        }
      }
    }
    return args;
  }

  private void roundtripGeneric(
      int ivSize,
      int wrappingKeySize,
      int secretSize,
      Provider wrappingProvider,
      Provider unwrappingProvider,
      boolean reuseCipher)
      throws Exception {
    final IvParameterSpec iv = (ivSize > 0) ? TestUtil.genIv(1, ivSize) : null;
    final SecretKey wrappingKey = getAesKey(wrappingKeySize);
    final byte[] secretBytes = TestUtil.getRandomBytes(secretSize);
    final SecretKey secret = new SecretKeySpec(secretBytes, "Generic");

    // wrap key
    Cipher c = getCipher(wrappingProvider);
    c.init(Cipher.WRAP_MODE, wrappingKey, iv);
    final byte[] wrappedKey = c.wrap(secret);
    assertFalse(Arrays.equals(secretBytes, wrappedKey));
    if (!reuseCipher) {
      c = getCipher(unwrappingProvider);
    } else {
      assertTrue(unwrappingProvider == null);
    }

    // unwrap key
    c.init(Cipher.UNWRAP_MODE, wrappingKey, iv);
    final Key unwrappedKey = c.unwrap(wrappedKey, "Generic", Cipher.SECRET_KEY);
    assertArraysHexEquals(secret.getEncoded(), unwrappedKey.getEncoded());
    assertEquals(secret, unwrappedKey);
  }

  @ParameterizedTest
  @MethodSource("getParamsGeneric")
  public void roundtripNativeSameCipherGeneric(int ivSize, int wrappingKeySize, int secretSize)
      throws Exception {
    roundtripGeneric(ivSize, wrappingKeySize, secretSize, TestUtil.NATIVE_PROVIDER, null, true);
  }

  @ParameterizedTest
  @MethodSource("getParamsGeneric")
  public void roundtripNativeNewCipherGeneric(int ivSize, int wrappingKeySize, int secretSize)
      throws Exception {
    roundtripGeneric(
        ivSize,
        wrappingKeySize,
        secretSize,
        TestUtil.NATIVE_PROVIDER,
        TestUtil.NATIVE_PROVIDER,
        false);
  }

  @ParameterizedTest
  @MethodSource("getParamsGeneric")
  public void roundtripNative2BouncyGeneric(int ivSize, int wrappingKeySize, int secretSize)
      throws Exception {
    roundtripGeneric(
        ivSize, wrappingKeySize, secretSize, TestUtil.NATIVE_PROVIDER, TestUtil.BC_PROVIDER, false);
  }

  @ParameterizedTest
  @MethodSource("getParamsGeneric")
  public void roundtripBouncy2nativeGeneric(int ivSize, int wrappingKeySize, int secretSize)
      throws Exception {
    roundtripGeneric(
        ivSize, wrappingKeySize, secretSize, TestUtil.BC_PROVIDER, TestUtil.NATIVE_PROVIDER, false);
  }

  @ParameterizedTest
  @MethodSource("getParamsGeneric")
  public void roundtripNative2JCEGeneric(int ivSize, int wrappingKeySize, int secretSize)
      throws Exception {
    TestUtil.assumeMinimumJavaVersion(
        17); // KW added to JCE in 17 https://bugs.openjdk.org/browse/JDK-8248268
    roundtripGeneric(ivSize, wrappingKeySize, secretSize, TestUtil.NATIVE_PROVIDER, null, false);
  }

  @ParameterizedTest
  @MethodSource("getParamsGeneric")
  public void roundtripJCE2nativeGeneric(int ivSize, int wrappingKeySize, int secretSize)
      throws Exception {
    TestUtil.assumeMinimumJavaVersion(
        17); // KW added to JCE in 17 https://bugs.openjdk.org/browse/JDK-8248268
    roundtripGeneric(ivSize, wrappingKeySize, secretSize, null, TestUtil.NATIVE_PROVIDER, false);
  }

  @Test
  public void testNativeSameCipherIncremental() throws Exception {
    final SecretKey wrappingKey = getAesKey(16);
    final byte[] secret = TestUtil.getRandomBytes(32);

    final Cipher encrypt = initCipher(Cipher.ENCRYPT_MODE, wrappingKey);
    encrypt.update(Arrays.copyOfRange(secret, 0, 16));
    encrypt.update(Arrays.copyOfRange(secret, 16, 32));
    final byte[] ciphertext = encrypt.doFinal();
    assertFalse(Arrays.equals(secret, ciphertext));

    final Cipher decrypt = initCipher(Cipher.DECRYPT_MODE, wrappingKey);
    decrypt.update(ciphertext);
    final byte[] plaintext = decrypt.doFinal();
    assertArraysHexEquals(secret, plaintext);
  }

  @Test
  public void testNativeProviderAlias() throws Exception {
    // this test asserts that all expected aliases for the AES KW cipher
    // are adequatly supplied by the native provider
    for (String alias : KW_CIPHER_ALIASES) {
      Cipher cipher = Cipher.getInstance(alias, TestUtil.NATIVE_PROVIDER);
      assertEquals(cipher.getAlgorithm(), alias);
    }
  }

  @Test
  public void testEngineGetOutputSize() throws Exception {
    final int[] inputSizes = new int[] {16, 32};
    final SecretKey kek = getAesKey(128 / 8);
    final Cipher encrypt = initCipher(Cipher.ENCRYPT_MODE, kek);
    // first pass, no buffered data
    for (int inputSize : inputSizes) {
      assertTrue(encrypt.getOutputSize(inputSize) % 8 == 0);
      assertTrue(encrypt.getOutputSize(inputSize) == inputSize + 8);
    }
    // second pass, buffer data
    int bytesBuffered = 0;
    for (int inputSize : inputSizes) {
      encrypt.update(new byte[inputSize]);
      bytesBuffered += inputSize;
      assertTrue(encrypt.getOutputSize(0) == bytesBuffered + 8);
    }
    int finalOutputSize = encrypt.getOutputSize(0);
    byte[] ciphertext = encrypt.doFinal();
    assertEquals(ciphertext.length, finalOutputSize);

    Cipher decrypt = initCipher(Cipher.DECRYPT_MODE, kek);
    // first pass, no buffered data
    for (int inputSize : inputSizes) {
      assertTrue(decrypt.getOutputSize(inputSize) == Math.max(inputSize - 8, 8));
    }
    // second pass, buffer data
    for (int inputSize : inputSizes) {
      decrypt.update(new byte[inputSize]);
    }
    // reset and update w/ ciphertext otherwise decrypt will fail.
    decrypt.init(Cipher.DECRYPT_MODE, kek);
    decrypt.update(ciphertext);
    finalOutputSize = decrypt.getOutputSize(0);
    assertTrue(decrypt.doFinal().length <= finalOutputSize);
  }

  private static final int[] CIPHER_MODES =
      new int[] {Cipher.ENCRYPT_MODE, Cipher.WRAP_MODE, Cipher.DECRYPT_MODE, Cipher.UNWRAP_MODE};

  private static List<Arguments> getCipherModeParams() {
    List<Arguments> args = new ArrayList<>();
    for (int mode : CIPHER_MODES) {
      args.add(Arguments.of(mode));
    }
    return args;
  }

  @ParameterizedTest
  @MethodSource("getCipherModeParams")
  public void testEngineGetParametersAndIv(int mode) throws Exception {
    TestUtil.assumeMinimumJavaVersion(
        17); // KW added to JCE in 17 https://bugs.openjdk.org/browse/JDK-8248268

    final SecretKey kek = getAesKey(128 / 8);
    final IvParameterSpec iv = TestUtil.genIv(1, 8);

    final Cipher c1 = getCipher(TestUtil.NATIVE_PROVIDER);
    c1.init(mode, kek);
    assertTrue(c1.getParameters() == null);
    assertTrue(c1.getIV() == null);

    final Cipher c2 = getCipher(TestUtil.NATIVE_PROVIDER);
    c2.init(mode, kek, (AlgorithmParameterSpec) null, (SecureRandom) null);
    assertTrue(c2.getParameters() == null);
    assertTrue(c2.getIV() == null);

    final Cipher c3 = getCipher(TestUtil.NATIVE_PROVIDER);
    c3.init(mode, kek, (AlgorithmParameters) null, (SecureRandom) null);
    assertTrue(c3.getParameters() == null);
    assertTrue(c3.getIV() == null);

    final Cipher c4 = getCipher(TestUtil.NATIVE_PROVIDER);
    c4.init(mode, kek, iv);
    assertTrue(c4.getParameters() != null);
    assertTrue(c4.getIV() != null);
    assertArraysHexEquals(c4.getIV(), iv.getIV());
  }

  @Test
  public void testBadInputs_setModeAndPadding() throws Throwable {
    final Object spi = sneakyConstruct(SPI_CLASS.getName(), TestUtil.NATIVE_PROVIDER);

    // engineSetPadding
    assertThrows(
        GeneralSecurityException.class,
        () -> Cipher.getInstance("AES/OTHER/Padding", TestUtil.NATIVE_PROVIDER));
    assertThrows(
        GeneralSecurityException.class,
        () -> Cipher.getInstance("AES/KW/Other", TestUtil.NATIVE_PROVIDER));
    sneakyInvoke(spi, "engineSetPadding", "NoPadding");

    // engineSetMode
    assertThrows(GeneralSecurityException.class, () -> sneakyInvoke(spi, "engineSetMode", "OTHER"));
    assertThrows(
        GeneralSecurityException.class, () -> sneakyInvoke(spi, "engineSetPadding", "Other"));
    sneakyInvoke(spi, "engineSetMode", "KW");
  }

  @Test
  public void testBadInputs_getBlockAndKeySize() throws Throwable {
    final Cipher c = getCipher(TestUtil.NATIVE_PROVIDER);
    assertEquals(128 / 8, c.getBlockSize());
    final Object spi = sneakyConstruct(SPI_CLASS.getName(), TestUtil.NATIVE_PROVIDER);
    assertThrows(InvalidKeyException.class, () -> sneakyInvoke(spi, "engineGetKeySize", NULL_KEY));
    sneakyInvoke(spi, "engineGetKeySize", getAesKey(128 / 8));
    sneakyInvoke(spi, "engineGetKeySize", getAesKey(256 / 8));
  }

  @Test
  public void testBadInputs_getOutputSize() throws Throwable {
    final SecretKey kek = getAesKey(128 / 8);
    final Cipher c = initCipher(Cipher.ENCRYPT_MODE, kek);
    assertThrows(ArithmeticException.class, () -> c.getOutputSize(Integer.MAX_VALUE));
    c.update(new byte[1024]);
    assertThrows(ArithmeticException.class, () -> c.getOutputSize(Integer.MAX_VALUE));
  }

  @Test
  public void testBadInputs_init() throws Throwable {
    final Object spi = sneakyConstruct(SPI_CLASS.getName(), TestUtil.NATIVE_PROVIDER);

    // Bad mode
    assertThrows(
        UnsupportedOperationException.class,
        () -> sneakyInvoke(spi, "engineInit", -1, null, null, null));

    // Bad keys
    assertThrows(
        InvalidKeyException.class,
        () -> sneakyInvoke(spi, "engineInit", Cipher.WRAP_MODE, /*key*/ null, /*spec*/ null, null));
    final Key badKey1 = new SecretKeySpec(new byte[128 / 8], "Generic");
    assertThrows(
        InvalidKeyException.class,
        () -> sneakyInvoke(spi, "engineInit", Cipher.WRAP_MODE, badKey1, null, null));
    assertThrows(
        InvalidKeyException.class,
        () -> sneakyInvoke(spi, "engineInit", Cipher.WRAP_MODE, NULL_KEY, null, null));

    // Bad IV
    final SecretKey key = getAesKey(128 / 8);
    final AlgorithmParameterSpec iv = new GCMParameterSpec(128, TestUtil.getRandomBytes(16));
    // using incorrect parameter type for the IV buffer
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> sneakyInvoke(spi, "engineInit", Cipher.WRAP_MODE, key, iv, null));
  }

  @Test
  public void testBadInputs_bufferSize() throws Exception {
    final SecretKey key = getAesKey(128 / 8);

    final Cipher wrap = initCipher(Cipher.WRAP_MODE, key);
    for (int secretSize : SECRET_SIZES) {
      final byte[] secretBytes1 = TestUtil.getRandomBytes(secretSize + 1);
      final byte[] secretBytes2 = TestUtil.getRandomBytes(secretSize - 1);
      assertThrows(
          InvalidKeyException.class, () -> wrap.wrap(new SecretKeySpec(secretBytes1, "Generic")));
      assertThrows(
          InvalidKeyException.class, () -> wrap.wrap(new SecretKeySpec(secretBytes2, "Generic")));
    }

    final Cipher encrypt = initCipher(Cipher.ENCRYPT_MODE, key);
    for (int secretSize : SECRET_SIZES) {
      final byte[] secretBytes = TestUtil.getRandomBytes(secretSize + 1);
      encrypt.update(secretBytes);
      assertThrows(BadPaddingException.class, () -> encrypt.doFinal());
    }
    for (int secretSize : SECRET_SIZES) {
      final byte[] secretBytes1 = TestUtil.getRandomBytes(secretSize + 1);
      final byte[] secretBytes2 = TestUtil.getRandomBytes(secretSize - 1);
      assertThrows(BadPaddingException.class, () -> encrypt.doFinal(secretBytes1));
      assertThrows(BadPaddingException.class, () -> encrypt.doFinal(secretBytes2));
    }
  }

  @Test
  public void testBadInputs_ivSize5() throws Exception {
    // RFC-3394 iv must point to an 8 byte value or be NULL to use the default
    testIncorrectIvSize(5);
  }

  @Test
  public void testBadInputs_ivSize10() throws Exception {
    // RFC-3394 iv must point to an 8 byte value or be NULL to use the default
    testIncorrectIvSize(10);
  }

  private void testIncorrectIvSize(int ivSize) throws Exception {
    final IvParameterSpec iv = TestUtil.genIv(1, ivSize);
    final Cipher c = getCipher(TestUtil.NATIVE_PROVIDER);
    final SecretKey key = getAesKey(128 / 8);

    assertThrows(InvalidAlgorithmParameterException.class, () -> c.init(Cipher.WRAP_MODE, key, iv));
    assertThrows(
        InvalidAlgorithmParameterException.class, () -> c.init(Cipher.ENCRYPT_MODE, key, iv));
  }

  @Test
  public void testBadInputs_update() throws Exception {
    final Cipher wrap = getCipher(TestUtil.NATIVE_PROVIDER);
    assertThrows(IllegalStateException.class, () -> wrap.update(new byte[8]));
    wrap.init(Cipher.WRAP_MODE, getAesKey(128 / 8));
    assertThrows(IllegalStateException.class, () -> wrap.update(new byte[8]));
    assertThrows(IllegalStateException.class, () -> wrap.update(new byte[8], 0, 1, new byte[0], 0));
    assertThrows(IllegalStateException.class, () -> wrap.update(new byte[8], 0, 1));

    final Cipher unwrap = initCipher(Cipher.UNWRAP_MODE, getAesKey(128 / 8));
    assertThrows(IllegalStateException.class, () -> unwrap.update(new byte[8]));
    assertThrows(
        IllegalStateException.class, () -> unwrap.update(new byte[8], 0, 1, new byte[0], 0));
    assertThrows(IllegalStateException.class, () -> unwrap.update(new byte[8], 0, 1));
  }

  @Test
  public void testBadInputs_doFinal() throws Exception {
    final Cipher c1 = getCipher(TestUtil.NATIVE_PROVIDER);
    assertThrows(IllegalStateException.class, () -> c1.doFinal(new byte[8]));

    final Cipher c2 = initCipher(Cipher.WRAP_MODE, getAesKey(128 / 8));
    assertThrows(IllegalStateException.class, () -> c2.doFinal(new byte[8]));

    final Cipher c3 = initCipher(Cipher.UNWRAP_MODE, getAesKey(128 / 8));
    assertThrows(IllegalStateException.class, () -> c3.doFinal(new byte[8]));

    final Cipher c4 = initCipher(Cipher.ENCRYPT_MODE, getAesKey(128 / 8));
    final int dataSize = 1024;
    c4.update(new byte[dataSize]);
    assertThrows(
        ShortBufferException.class, () -> c4.doFinal(new byte[8], 0, 1, new byte[dataSize + 1], 0));
  }

  @Test
  public void testBadInputs_wrapAndUnwrap() throws Exception {
    final Key key = getAesKey(128 / 8); // NOTE: use for both wrapping and being wrapped

    // Bad modes
    final Cipher c1 = initCipher(Cipher.UNWRAP_MODE, key);
    assertThrows(IllegalStateException.class, () -> c1.wrap(key));
    final Cipher c2 = initCipher(Cipher.ENCRYPT_MODE, key);
    assertThrows(IllegalStateException.class, () -> c2.wrap(key));
    final Cipher c3 = initCipher(Cipher.DECRYPT_MODE, key);
    assertThrows(IllegalStateException.class, () -> c3.wrap(key));
    final Cipher c4 = initCipher(Cipher.WRAP_MODE, key);
    final byte[] wrapped = c4.wrap(key);
    assertThrows(IllegalStateException.class, () -> c4.unwrap(wrapped, "AES", Cipher.SECRET_KEY));
    final Cipher c5 = initCipher(Cipher.ENCRYPT_MODE, key);
    assertThrows(IllegalStateException.class, () -> c5.unwrap(wrapped, "AES", Cipher.SECRET_KEY));
    final Cipher c6 = initCipher(Cipher.DECRYPT_MODE, key);
    assertThrows(IllegalStateException.class, () -> c6.unwrap(wrapped, "AES", Cipher.SECRET_KEY));

    // Bad key
    final Cipher wrap = initCipher(Cipher.WRAP_MODE, key);
    assertThrows(InvalidKeyException.class, () -> wrap.wrap(NULL_KEY));
  }

  @Test
  public void testBadInputs_wrongUnwrapKey() throws Exception {
    final SecretKey key1 = getAesKey(16);
    final SecretKey key2 = getAesKey(16);
    final SecretKey secret = new SecretKeySpec(TestUtil.getRandomBytes(32), "Generic");

    final Cipher wrap = initCipher(Cipher.WRAP_MODE, key1);
    final byte[] wrappedKey = wrap.wrap(secret);

    final Cipher unwrapKey2 = initCipher(Cipher.UNWRAP_MODE, key2);
    assertThrows(
        InvalidKeyException.class,
        () -> unwrapKey2.unwrap(wrappedKey, "Generic", Cipher.SECRET_KEY));

    final Cipher unwrapKey1 = initCipher(Cipher.UNWRAP_MODE, key1);
    final Key unwrappedKey = unwrapKey1.unwrap(wrappedKey, "Generic", Cipher.SECRET_KEY);
    assertArraysHexEquals(secret.getEncoded(), unwrappedKey.getEncoded());
  }

  @Test
  public void threadStorm() throws GeneralSecurityException, InterruptedException {
    final byte[] rngSeed = TestUtil.getRandomBytes(20);
    final SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");
    rng.setSeed(rngSeed);
    final int iterations = 500;
    final int threadCount = 48;

    // NOTE: these keys need to be deterministic, so pull them from the seeded rng
    final SecretKey[] keys = new SecretKey[3];
    byte[] buff = new byte[32];
    rng.nextBytes(buff);
    keys[0] = new SecretKeySpec(buff, 0, 16, "AES");
    rng.nextBytes(buff);
    keys[1] = new SecretKeySpec(buff, 0, 24, "AES");
    rng.nextBytes(buff);
    keys[2] = new SecretKeySpec(buff, 0, 32, "AES");

    final List<SecretKey> keyList = Arrays.asList(keys);
    final List<AesKeyWrapTestThread> threads = new ArrayList<>();
    for (int x = 0; x < threadCount; x++) {
      threads.add(
          new AesKeyWrapTestThread(
              KW_CIPHER_ALIASES, "AesKwThread-" + x, rng, iterations, keyList));
    }

    for (final AesKeyWrapTestThread t : threads) {
      t.start();
    }

    final List<Throwable> results = new ArrayList<>();
    for (final AesKeyWrapTestThread t : threads) {
      t.join();
      if (t.result != null) {
        results.add(t.result);
      }
    }
    if (!results.isEmpty()) {
      final AssertionError ex =
          new AssertionError(
              "Throwable while testing threads, RNG seed: " + Arrays.toString(rngSeed));
      for (Throwable t : results) {
        t.printStackTrace();
        ex.addSuppressed(t);
      }
      throw ex;
    }
  }

  // NOTE: this funciton is a convenience to make the test code cleaner
  //       across providers that use different aliases to provide the same
  //       Cipher. it relies on nativeProviderAliasTest to ensure that we
  //       provide ciphers across all expected aliases.
  private static Cipher getCipher(Provider provider) throws GeneralSecurityException {
    return TestUtil.getCipher(provider, KW_CIPHER_ALIASES);
  }

  private static Cipher initCipher(int mode, Key key) throws GeneralSecurityException {
    final Cipher c = getCipher(TestUtil.NATIVE_PROVIDER);
    c.init(mode, key);
    return c;
  }

  private static SecretKey getAesKey(int size) {
    return new SecretKeySpec(TestUtil.getRandomBytes(size), "AES");
  }
}
