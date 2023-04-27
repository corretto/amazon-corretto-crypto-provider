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
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
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
public final class AesKeyWrapPaddingTest {
  private static final Class<?> SPI_CLASS;

  static {
    try {
      SPI_CLASS = Class.forName("com.amazon.corretto.crypto.provider.AesKeyWrapPaddingSpi");
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

  private static final List<String> KWP_CIPHER_ALIASES =
      Arrays.asList("AESWRAPPAD", "AesWrapPad", "AES/KWP/NoPadding");

  private static final List<Integer> AES_KEY_SIZES = Arrays.asList(16, 24, 32);

  public static List<Arguments> getParamsGeneric() {
    final int[] secretSizes = {
      8, // https://datatracker.ietf.org/doc/html/rfc5649#section-4.1
      16, 24, 32, // AES keys
      512, 1024, 2048, 4096, // RSA keys
      4, 123, 900, 81, 99, 37, // weird sizes to exercise padding logic
    };
    List<Arguments> args = new ArrayList<>();
    for (int wrappingKeySize : AES_KEY_SIZES) {
      for (int secretSize : secretSizes) {
        args.add(Arguments.of(wrappingKeySize, secretSize - 1));
        args.add(Arguments.of(wrappingKeySize, secretSize));
        args.add(Arguments.of(wrappingKeySize, secretSize + 1));
      }
    }
    return args;
  }

  private void roundtripGeneric(
      int wrappingKeySize,
      int secretSize,
      Provider wrappingProvider,
      Provider unwrappingProvider,
      boolean reuseCipher)
      throws Exception {
    final SecureRandom ignored = null;
    final SecretKey wrappingKey = getAesKey(wrappingKeySize);

    byte[] secretBytes = TestUtil.getRandomBytes(secretSize);
    final SecretKey secret = new SecretKeySpec(secretBytes, "Generic");

    Cipher c = getCipher(wrappingProvider);
    c.init(Cipher.WRAP_MODE, wrappingKey, ignored);
    byte[] wrappedKey = c.wrap(secret);
    assertFalse(Arrays.equals(secretBytes, wrappedKey));
    if (!reuseCipher) {
      c = getCipher(unwrappingProvider);
    } else {
      assertTrue(unwrappingProvider == null);
    }
    c.init(Cipher.UNWRAP_MODE, wrappingKey, ignored);
    final int mode;
    Key unwrappedKey = c.unwrap(wrappedKey, "Generic", Cipher.SECRET_KEY);
    assertArraysHexEquals(secret.getEncoded(), unwrappedKey.getEncoded());
    assertEquals(secret, unwrappedKey);
  }

  @ParameterizedTest
  @MethodSource("getParamsGeneric")
  public void roundtripNativeSameCipherGeneric(int wrappingKeySize, int secretSize)
      throws Exception {
    roundtripGeneric(wrappingKeySize, secretSize, TestUtil.NATIVE_PROVIDER, null, true);
  }

  @ParameterizedTest
  @MethodSource("getParamsGeneric")
  public void roundtripNativeNewCipherGeneric(int wrappingKeySize, int secretSize)
      throws Exception {
    roundtripGeneric(
        wrappingKeySize, secretSize, TestUtil.NATIVE_PROVIDER, TestUtil.NATIVE_PROVIDER, false);
  }

  @ParameterizedTest
  @MethodSource("getParamsGeneric")
  public void roundtripNative2BouncyGeneric(int wrappingKeySize, int secretSize) throws Exception {
    roundtripGeneric(
        wrappingKeySize, secretSize, TestUtil.NATIVE_PROVIDER, TestUtil.BC_PROVIDER, false);
  }

  @ParameterizedTest
  @MethodSource("getParamsGeneric")
  public void roundtripBouncy2nativeGeneric(int wrappingKeySize, int secretSize) throws Exception {
    roundtripGeneric(
        wrappingKeySize, secretSize, TestUtil.BC_PROVIDER, TestUtil.NATIVE_PROVIDER, false);
  }

  @ParameterizedTest
  @MethodSource("getParamsGeneric")
  public void roundtripNative2JCEGeneric(int wrappingKeySize, int secretSize) throws Exception {
    TestUtil.assumeMinimumJavaVersion(
        17); // KWP added to JCE in 17 https://bugs.openjdk.org/browse/JDK-8248268
    roundtripGeneric(wrappingKeySize, secretSize, TestUtil.NATIVE_PROVIDER, null, false);
  }

  @ParameterizedTest
  @MethodSource("getParamsGeneric")
  public void roundtripJCE2nativeGeneric(int wrappingKeySize, int secretSize) throws Exception {
    TestUtil.assumeMinimumJavaVersion(
        17); // KWP added to JCE in 17 https://bugs.openjdk.org/browse/JDK-8248268
    roundtripGeneric(wrappingKeySize, secretSize, null, TestUtil.NATIVE_PROVIDER, false);
  }

  public static List<Arguments> getParamsAsymmetric() throws GeneralSecurityException {
    final String[] ecCurveNames = {"secp224r1", "secp256r1", "secp384r1", "secp521r1"};
    final List<Integer> rsaKeySizes =
        TestUtil.isFips() ? Arrays.asList(2048, 4096) : Arrays.asList(512, 1024, 2048, 4096);
    List<Arguments> args = new ArrayList<>();
    KeyPairGenerator kpg;
    for (int wrappingKeySize : AES_KEY_SIZES) {
      kpg = KeyPairGenerator.getInstance("EC", TestUtil.NATIVE_PROVIDER);
      for (String curve : ecCurveNames) {
        kpg.initialize(new ECGenParameterSpec(curve));
        String display = String.format("EC(%s)", curve);
        args.add(Arguments.of(wrappingKeySize, kpg.generateKeyPair(), display));
      }
      kpg = KeyPairGenerator.getInstance("RSA", TestUtil.NATIVE_PROVIDER);
      for (int bits : rsaKeySizes) {
        kpg.initialize(bits);
        String display = String.format("RSA(%d)", bits);
        args.add(Arguments.of(wrappingKeySize, kpg.generateKeyPair(), display));
      }
    }
    return args;
  }

  private void roundtripAsymmetric(
      int wrappingKeySize,
      KeyPair keyPair,
      Provider wrappingProvider,
      Provider unwrappingProvider,
      boolean reuseCipher)
      throws Exception {
    final SecureRandom ignored = null;
    final SecretKey wrappingKey = getAesKey(wrappingKeySize);

    Cipher c = getCipher(wrappingProvider);
    c.init(Cipher.WRAP_MODE, wrappingKey);
    byte[] wrappedPublicKey = c.wrap(keyPair.getPublic());
    byte[] wrappedPrivateKey = c.wrap(keyPair.getPrivate());
    assertFalse(Arrays.equals(keyPair.getPublic().getEncoded(), wrappedPublicKey));
    assertFalse(Arrays.equals(keyPair.getPrivate().getEncoded(), wrappedPrivateKey));
    if (!reuseCipher) {
      c = getCipher(unwrappingProvider);
    } else {
      assertTrue(unwrappingProvider == null);
    }
    c.init(Cipher.UNWRAP_MODE, wrappingKey);
    Key unwrappedPublicKey =
        c.unwrap(wrappedPublicKey, keyPair.getPublic().getAlgorithm(), Cipher.PUBLIC_KEY);
    Key unwrappedPrivateKey =
        c.unwrap(wrappedPrivateKey, keyPair.getPrivate().getAlgorithm(), Cipher.PRIVATE_KEY);
    assertArraysHexEquals(keyPair.getPublic().getEncoded(), unwrappedPublicKey.getEncoded());
    assertArraysHexEquals(keyPair.getPrivate().getEncoded(), unwrappedPrivateKey.getEncoded());
    assertEquals(keyPair.getPublic(), unwrappedPublicKey);
    assertEquals(keyPair.getPrivate(), unwrappedPrivateKey);

    // By passing it through the factory we ensure that it is an understandable type
    final KeyFactory kf =
        KeyFactory.getInstance(keyPair.getPublic().getAlgorithm(), TestUtil.NATIVE_PROVIDER);
    assertArraysHexEquals(
        kf.getKeySpec(keyPair.getPrivate(), PKCS8EncodedKeySpec.class).getEncoded(),
        kf.getKeySpec(unwrappedPrivateKey, PKCS8EncodedKeySpec.class).getEncoded());
    assertArraysHexEquals(
        kf.getKeySpec(keyPair.getPublic(), X509EncodedKeySpec.class).getEncoded(),
        kf.getKeySpec(unwrappedPublicKey, X509EncodedKeySpec.class).getEncoded());
  }

  @ParameterizedTest
  @MethodSource("getParamsAsymmetric")
  public void roundtripNativeSameCipherAsymmetric(
      int wrappingKeySize, KeyPair keyPair, String display) throws Exception {
    roundtripAsymmetric(wrappingKeySize, keyPair, TestUtil.NATIVE_PROVIDER, null, true);
  }

  @ParameterizedTest
  @MethodSource("getParamsAsymmetric")
  public void roundtripNativeNewCipherAsymmetric(
      int wrappingKeySize, KeyPair keyPair, String display) throws Exception {
    roundtripAsymmetric(
        wrappingKeySize, keyPair, TestUtil.NATIVE_PROVIDER, TestUtil.NATIVE_PROVIDER, false);
  }

  @ParameterizedTest
  @MethodSource("getParamsAsymmetric")
  public void roundtripNative2BouncyAsymmetric(int wrappingKeySize, KeyPair keyPair, String display)
      throws Exception {
    // NOTE: BC is unwrapping EC private keys differently from ACCP and
    //       JCE, then remove this assumption from the parameterized test.
    //       in the meantime, we have a temporary test below showing that
    //       while the unwrapping with BC an ACCP-wrapped EC key does not
    //       produce a byte-for-byte replica of the original, it's still
    //       possible to use both keys for signing.
    org.junit.jupiter.api.Assumptions.assumeTrue(!display.startsWith("EC("));
    roundtripAsymmetric(
        wrappingKeySize, keyPair, TestUtil.NATIVE_PROVIDER, TestUtil.BC_PROVIDER, false);
  }

  @Test
  public void testNative2BouncyECPrivateKeySignaturesOK() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", TestUtil.NATIVE_PROVIDER);
    kpg.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair keyPair = kpg.generateKeyPair();
    final SecretKey wrappingKey = getAesKey(128 / 8);

    Cipher wrapper = Cipher.getInstance("AESWRAPPAD", TestUtil.NATIVE_PROVIDER);
    wrapper.init(Cipher.WRAP_MODE, wrappingKey);
    byte[] wrappedPrivateKey = wrapper.wrap(keyPair.getPrivate());
    wrapper = Cipher.getInstance("AESWRAPPAD", TestUtil.BC_PROVIDER);
    wrapper.init(Cipher.WRAP_MODE, wrappingKey);
    wrapper.init(Cipher.UNWRAP_MODE, wrappingKey);
    Key unwrappedPrivateKey = wrapper.unwrap(wrappedPrivateKey, "EC", Cipher.PRIVATE_KEY);

    Signature signer = Signature.getInstance("SHA256withECDSA", TestUtil.NATIVE_PROVIDER);
    final byte[] message = TestUtil.getRandomBytes(1024);
    signer.initSign(keyPair.getPrivate());
    signer.update(message);
    final byte[] goodSignature = signer.sign();
    signer.initSign((PrivateKey) unwrappedPrivateKey);
    signer.update(message);
    final byte[] unwrappedKeySignature = signer.sign();
    assertFalse(Arrays.equals(keyPair.getPrivate().getEncoded(), unwrappedPrivateKey.getEncoded()));
    assertFalse(Arrays.equals(goodSignature, unwrappedKeySignature));

    Signature verifier = Signature.getInstance("SHA256withECDSA", TestUtil.NATIVE_PROVIDER);
    verifier.initVerify(keyPair.getPublic());
    verifier.update(message);
    assertTrue(verifier.verify(goodSignature));
    verifier.initVerify(keyPair.getPublic());
    verifier.update(message);
    assertTrue(verifier.verify(unwrappedKeySignature));
  }

  @ParameterizedTest
  @MethodSource("getParamsAsymmetric")
  public void roundtripBouncy2nativeAsymmetric(int wrappingKeySize, KeyPair keyPair, String display)
      throws Exception {
    roundtripAsymmetric(
        wrappingKeySize, keyPair, TestUtil.BC_PROVIDER, TestUtil.NATIVE_PROVIDER, false);
  }

  @ParameterizedTest
  @MethodSource("getParamsAsymmetric")
  public void roundtripNative2JCEAsymmetric(int wrappingKeySize, KeyPair keyPair, String display)
      throws Exception {
    TestUtil.assumeMinimumJavaVersion(
        17); // KWP added to JCE in 17 https://bugs.openjdk.org/browse/JDK-8248268
    roundtripAsymmetric(wrappingKeySize, keyPair, TestUtil.NATIVE_PROVIDER, null, false);
  }

  @ParameterizedTest
  @MethodSource("getParamsAsymmetric")
  public void roundtripJCE2nativeAsymmetric(int wrappingKeySize, KeyPair keyPair, String display)
      throws Exception {
    TestUtil.assumeMinimumJavaVersion(
        17); // KWP added to JCE in 17 https://bugs.openjdk.org/browse/JDK-8248268
    roundtripAsymmetric(wrappingKeySize, keyPair, null, TestUtil.NATIVE_PROVIDER, false);
  }

  public static List<Arguments> getParamsIncremental() {
    final int[] stepSizes = new int[] {1, 7, 9, 16, 17, 32};
    final int[] doFinalSizes = new int[] {0, 1, 7, 9, 16, 17, 32};
    final List<Arguments> args = new ArrayList<>();
    for (Arguments other : getParamsGeneric()) {
      for (int stepSize : stepSizes) {
        for (int doFinalSize : doFinalSizes) {
          args.add(Arguments.of(other.get()[0], other.get()[1], stepSize, doFinalSize));
        }
      }
    }
    return args;
  }

  private void roundtripIncremental(
      int wrappingKeySize, int secretSize, int stepSize, int doFinalSize) throws Exception {
    final SecretKey wrappingKey = getAesKey(wrappingKeySize);
    final byte[] secret = TestUtil.getRandomBytes(secretSize);

    Cipher c = getCipher(TestUtil.NATIVE_PROVIDER);
    c.init(Cipher.ENCRYPT_MODE, wrappingKey);
    int updateLimit = secret.length - doFinalSize;
    // if doFinalSize is greater than the data we're working with, then
    // don't add any more data in the doFinal call.
    if (updateLimit < 0) {
      updateLimit = secret.length;
    }
    for (int ii = 0; ii < updateLimit; ii += stepSize) {
      byte[] chunk = Arrays.copyOfRange(secret, ii, Math.min(ii + stepSize, updateLimit));
      c.update(chunk);
    }
    byte[] ciphertext = c.doFinal(Arrays.copyOfRange(secret, updateLimit, secret.length));
    assertFalse(Arrays.equals(secret, ciphertext));
    c.init(Cipher.DECRYPT_MODE, wrappingKey);
    updateLimit = ciphertext.length - doFinalSize;
    // if doFinalSize is greater than the data we're working with, then
    // don't add any more data in the doFinal call.
    if (updateLimit < 0) {
      updateLimit = ciphertext.length;
    }
    for (int ii = 0; ii < updateLimit; ii += stepSize) {
      byte[] chunk = Arrays.copyOfRange(ciphertext, ii, Math.min(ii + stepSize, updateLimit));
      c.update(chunk);
    }
    byte[] plaintext = c.doFinal(Arrays.copyOfRange(ciphertext, updateLimit, ciphertext.length));
    assertArraysHexEquals(secret, plaintext);
  }

  @ParameterizedTest
  @MethodSource("getParamsIncremental")
  public void roundtripNativeSameCipherIncremental(
      int wrappingKeySize, int secretSize, int stepSize, int doFinalSize) throws Exception {
    roundtripIncremental(wrappingKeySize, secretSize, stepSize, doFinalSize);
  }

  @Test
  public void nativeProviderAliasTest() throws Exception {
    // this test asserts that all expected aliases for the AES KWP cipher
    // are adequatly supplied by the native provider
    for (String alias : KWP_CIPHER_ALIASES) {
      Cipher.getInstance(alias, TestUtil.NATIVE_PROVIDER);
    }
  }

  @Test
  public void testEngineGetOtputSize() throws Exception {
    final int[] inputSizes = new int[] {1, 5, 9, 16, 31, 32};
    Cipher c = getCipher(TestUtil.NATIVE_PROVIDER);
    final SecretKey kek = getAesKey(128 / 8);
    c.init(Cipher.ENCRYPT_MODE, kek);
    // first pass, no buffered data
    for (int inputSize : inputSizes) {
      assertTrue(c.getOutputSize(inputSize) % 8 == 0);
      assertTrue(c.getOutputSize(inputSize) >= inputSize + 8);
    }
    // second pass, buffer data
    int bytesBuffered = 0;
    for (int inputSize : inputSizes) {
      c.update(new byte[inputSize]);
      bytesBuffered += inputSize;
      assertTrue(c.getOutputSize(0) >= bytesBuffered + 8);
    }
    int finalOutputSize = c.getOutputSize(0);
    byte[] ciphertext = c.doFinal();
    assertEquals(ciphertext.length, finalOutputSize);

    c.init(Cipher.DECRYPT_MODE, kek);
    // first pass, no buffered data
    for (int inputSize : inputSizes) {
      assertTrue(c.getOutputSize(inputSize) == Math.max(inputSize - 8, 8));
    }
    // second pass, buffer data
    for (int inputSize : inputSizes) {
      c.update(new byte[inputSize]);
    }
    // reset and update w/ ciphertext otherwise decrypt will fail.
    c.init(Cipher.DECRYPT_MODE, kek);
    c.update(ciphertext);
    finalOutputSize = c.getOutputSize(0);
    assertTrue(c.doFinal().length <= finalOutputSize);
  }

  @Test
  public void testEngineGetParametersAndIv() throws Exception {
    Cipher c = getCipher(TestUtil.NATIVE_PROVIDER);
    assertTrue(c.getParameters() == null);
    assertTrue(c.getIV() == null);
    final int[] modes =
        new int[] {
          Cipher.ENCRYPT_MODE, Cipher.ENCRYPT_MODE, Cipher.ENCRYPT_MODE, Cipher.ENCRYPT_MODE
        };
    for (int mode : modes) {
      c.init(mode, getAesKey(128 / 8));
      assertTrue(c.getParameters() == null);
      assertTrue(c.getIV() == null);
      c.init(mode, getAesKey(128 / 8), (AlgorithmParameterSpec) null, (SecureRandom) null);
      assertTrue(c.getParameters() == null);
      assertTrue(c.getIV() == null);
      c.init(mode, getAesKey(128 / 8), (AlgorithmParameters) null, (SecureRandom) null);
      assertTrue(c.getParameters() == null);
      assertTrue(c.getIV() == null);
    }
  }

  @ParameterizedTest
  @MethodSource("getParamsIncremental")
  public void testUpdateDoFinalOverloads(
      int wrappingKeySize, int secretSize, int stepSize, int doFinalSize) throws Exception {
    final Cipher c1 = getCipher(TestUtil.NATIVE_PROVIDER);
    final Cipher c2 = getCipher(TestUtil.NATIVE_PROVIDER);
    final Cipher c3 = getCipher(TestUtil.NATIVE_PROVIDER);
    final Cipher c4 = getCipher(TestUtil.NATIVE_PROVIDER);
    final Key kek = getAesKey(wrappingKeySize);
    final byte[] plaintext = TestUtil.getRandomBytes(secretSize);
    byte[] input = plaintext;
    for (int mode : new int[] {Cipher.ENCRYPT_MODE, Cipher.DECRYPT_MODE}) {
      for (Cipher c : new Cipher[] {c1, c2, c3, c4}) {
        c.init(mode, kek);
      }
      final int endIdx = input.length - doFinalSize > 0 ? input.length - doFinalSize : input.length;
      for (int ii = 0; ii < endIdx; ii += stepSize) {
        final int inLen = Math.min(stepSize, endIdx - ii);
        assertTrue(null == c1.update(Arrays.copyOfRange(input, ii, ii + inLen)));
        assertTrue(null == c2.update(input, ii, inLen));
        assertEquals(0, c3.update(input, ii, inLen, new byte[0], 0));
      }
      final int inLen = input.length - endIdx;
      final byte[] output = c4.doFinal(input);
      assertArraysHexEquals(output, c1.doFinal(Arrays.copyOfRange(input, endIdx, input.length)));
      assertArraysHexEquals(output, c2.doFinal(input, endIdx, inLen));
      final byte[] c3Output = new byte[c3.getOutputSize(inLen)];
      final int c3OutLen = c3.doFinal(input, endIdx, inLen, c3Output, 0);
      assertEquals(output.length, c3OutLen);
      assertArraysHexEquals(output, Arrays.copyOfRange(c3Output, 0, c3OutLen));
      input = output; // set ciphertext as input after first iter.
    }
  }

  @Test
  public void testUpdateWithOversizedInputLen() throws Exception {
    final Cipher c = getCipher(TestUtil.NATIVE_PROVIDER);
    final Key kek = getAesKey(128 / 8);
    c.init(Cipher.ENCRYPT_MODE, kek);
    final byte[] plaintext = TestUtil.getRandomBytes(1024);
    assertThrows(
        IllegalArgumentException.class, () -> c.update(plaintext, 0, plaintext.length + 1));
    assertThrows(IllegalArgumentException.class, () -> c.update(plaintext, 1, plaintext.length));
    assertThrows(
        IllegalArgumentException.class, () -> c.update(plaintext, plaintext.length + 1, 0));
    c.update(plaintext, 0, plaintext.length);
    final byte[] ciphertext = c.doFinal();
    c.init(Cipher.DECRYPT_MODE, kek);
    assertThrows(
        IllegalArgumentException.class, () -> c.doFinal(ciphertext, 0, ciphertext.length + 1));
    assertThrows(IllegalArgumentException.class, () -> c.doFinal(ciphertext, 1, ciphertext.length));
    assertThrows(
        IllegalArgumentException.class, () -> c.doFinal(ciphertext, ciphertext.length + 1, 0));
    assertArraysHexEquals(plaintext, c.doFinal(ciphertext, 0, ciphertext.length));
  }

  @Test
  public void testBadInputs_setModeAndPadding() throws Throwable {
    Object spi = sneakyConstruct(SPI_CLASS.getName(), TestUtil.NATIVE_PROVIDER);

    // engineSetPadding
    assertThrows(
        GeneralSecurityException.class,
        () -> Cipher.getInstance("AES/OTHER/NoPadding", TestUtil.NATIVE_PROVIDER));
    assertThrows(
        GeneralSecurityException.class,
        () -> Cipher.getInstance("AES/KWP/Other", TestUtil.NATIVE_PROVIDER));
    sneakyInvoke(spi, "engineSetPadding", "NoPadding");

    // engineSetMode
    assertThrows(GeneralSecurityException.class, () -> sneakyInvoke(spi, "engineSetMode", "OTHER"));
    assertThrows(
        GeneralSecurityException.class, () -> sneakyInvoke(spi, "engineSetPadding", "Other"));
    sneakyInvoke(spi, "engineSetMode", "KWP");
  }

  @Test
  public void testBadInputs_getBlockAndKeySize() throws Throwable {
    Cipher c = getCipher(TestUtil.NATIVE_PROVIDER);
    assertEquals(128 / 8, c.getBlockSize());
    Object spi = sneakyConstruct(SPI_CLASS.getName(), TestUtil.NATIVE_PROVIDER);
    assertThrows(InvalidKeyException.class, () -> sneakyInvoke(spi, "engineGetKeySize", NULL_KEY));
    sneakyInvoke(spi, "engineGetKeySize", getAesKey(128 / 8));
    sneakyInvoke(spi, "engineGetKeySize", getAesKey(256 / 8));
  }

  @Test
  public void testBadInputs_getOutputSize() throws Throwable {
    Cipher c = getCipher(TestUtil.NATIVE_PROVIDER);
    final SecretKey kek = getAesKey(128 / 8);
    c.init(Cipher.ENCRYPT_MODE, kek);
    assertThrows(ArithmeticException.class, () -> c.getOutputSize(Integer.MAX_VALUE));
    c.update(new byte[1024]);
    assertThrows(ArithmeticException.class, () -> c.getOutputSize(Integer.MAX_VALUE));
  }

  @Test
  public void testBadInputs_init() throws Throwable {
    Object spi = sneakyConstruct(SPI_CLASS.getName(), TestUtil.NATIVE_PROVIDER);

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
  }

  @Test
  public void testBadInputs_update() throws Exception {
    Cipher c = getCipher(TestUtil.NATIVE_PROVIDER);
    assertThrows(IllegalStateException.class, () -> c.update(new byte[1]));
    c.init(Cipher.WRAP_MODE, getAesKey(128 / 8));
    assertThrows(IllegalStateException.class, () -> c.update(new byte[1]));
    assertThrows(IllegalStateException.class, () -> c.update(new byte[1], 0, 1, new byte[0], 0));
    assertThrows(IllegalStateException.class, () -> c.update(new byte[1], 0, 1));
    c.init(Cipher.UNWRAP_MODE, getAesKey(128 / 8));
    assertThrows(IllegalStateException.class, () -> c.update(new byte[1]));
    assertThrows(IllegalStateException.class, () -> c.update(new byte[1], 0, 1, new byte[0], 0));
    assertThrows(IllegalStateException.class, () -> c.update(new byte[1], 0, 1));
  }

  @Test
  public void testBadInputs_doFinal() throws Exception {
    Cipher c = getCipher(TestUtil.NATIVE_PROVIDER);
    assertThrows(IllegalStateException.class, () -> c.doFinal(new byte[1]));
    c.init(Cipher.WRAP_MODE, getAesKey(128 / 8));
    assertThrows(IllegalStateException.class, () -> c.doFinal(new byte[1]));
    c.init(Cipher.UNWRAP_MODE, getAesKey(128 / 8));
    assertThrows(IllegalStateException.class, () -> c.doFinal(new byte[1]));
    c.init(Cipher.ENCRYPT_MODE, getAesKey(128 / 8));
    final int dataSize = 1024;
    c.update(new byte[dataSize]);
    assertThrows(
        ShortBufferException.class, () -> c.doFinal(new byte[1], 0, 1, new byte[dataSize + 1], 0));
  }

  @Test
  public void testBadInputs_wrapAndUnwrap() throws Exception {
    Key key = getAesKey(128 / 8); // NOTE: use for both wrapping and being wrapped
    Cipher c = getCipher(TestUtil.NATIVE_PROVIDER);

    // Bad modes
    c.init(Cipher.UNWRAP_MODE, key);
    assertThrows(IllegalStateException.class, () -> c.wrap(key));
    c.init(Cipher.ENCRYPT_MODE, key);
    assertThrows(IllegalStateException.class, () -> c.wrap(key));
    c.init(Cipher.DECRYPT_MODE, key);
    assertThrows(IllegalStateException.class, () -> c.wrap(key));
    c.init(Cipher.WRAP_MODE, key);
    byte[] wrapped = c.wrap(key);
    assertThrows(IllegalStateException.class, () -> c.unwrap(wrapped, "AES", Cipher.SECRET_KEY));
    c.init(Cipher.ENCRYPT_MODE, key);
    assertThrows(IllegalStateException.class, () -> c.unwrap(wrapped, "AES", Cipher.SECRET_KEY));
    c.init(Cipher.DECRYPT_MODE, key);
    assertThrows(IllegalStateException.class, () -> c.unwrap(wrapped, "AES", Cipher.SECRET_KEY));

    // Bad key
    c.init(Cipher.WRAP_MODE, key);
    assertThrows(InvalidKeyException.class, () -> c.wrap(NULL_KEY));
  }

  @Test
  public void threadStorm() throws GeneralSecurityException, InterruptedException {
    final byte[] rngSeed = TestUtil.getRandomBytes(20);
    System.out.println("RNG Seed: " + Arrays.toString(rngSeed));
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
    final List<TestThread> threads = new ArrayList<>();
    for (int x = 0; x < threadCount; x++) {
      threads.add(new TestThread("AesKwpThread-" + x, rng, iterations, keyList));
    }

    for (final TestThread t : threads) {
      t.start();
    }

    final List<Throwable> results = new ArrayList<>();
    for (final TestThread t : threads) {
      t.join();
      if (t.result != null) {
        results.add(t.result);
      }
    }
    if (!results.isEmpty()) {
      final AssertionError ex = new AssertionError("Throwable while testing threads");
      for (Throwable t : results) {
        t.printStackTrace();
        ex.addSuppressed(t);
      }
      throw ex;
    }
  }

  private static class TestThread extends Thread {
    private final SecureRandom rnd_;
    private final List<SecretKey> keys_;
    private final Cipher enc_;
    private final Cipher dec_;
    private final int iterations_;
    private final byte[] plaintext_;
    public volatile Throwable result = null;

    public TestThread(String name, SecureRandom rng, int iterations, List<SecretKey> keys)
        throws GeneralSecurityException {
      super(name);
      iterations_ = iterations;
      keys_ = keys;
      enc_ = getCipher(TestUtil.NATIVE_PROVIDER);
      dec_ = getCipher(TestUtil.NATIVE_PROVIDER);
      plaintext_ = new byte[64];
      rnd_ = SecureRandom.getInstance("SHA1PRNG");
      byte[] seed = new byte[20];
      rng.nextBytes(seed);
      rnd_.setSeed(seed);
      rnd_.nextBytes(plaintext_);
    }

    @Override
    public void run() {
      for (int x = 0; x < iterations_; x++) {
        try {
          // Choose a key and encrypt the plaintext as if it were a key
          final SecretKey kek = keys_.get(rnd_.nextInt(keys_.size()));
          enc_.init(Cipher.ENCRYPT_MODE, kek);
          dec_.init(Cipher.DECRYPT_MODE, kek);
          assertArraysHexEquals(plaintext_, dec_.doFinal(enc_.doFinal(plaintext_)));

          // Then, pick a random key from the list and wrap/unwrap it
          final Key toWrap = keys_.get(rnd_.nextInt(keys_.size()));
          enc_.init(Cipher.WRAP_MODE, kek);
          dec_.init(Cipher.UNWRAP_MODE, kek);
          final Key unwrapped = dec_.unwrap(enc_.wrap(toWrap), "AES", Cipher.SECRET_KEY);
          assertArraysHexEquals(toWrap.getEncoded(), unwrapped.getEncoded());
        } catch (final Throwable ex) {
          result = ex;
          return;
        }
      }
    }
  }

  // NOTE: this funciton is a convenience to make the test code cleaner
  //       across providers that use different aliases to provide the same
  //       Cipher. it relies on nativeProviderAliasTest to ensure that we
  //       provide ciphers across all expected aliases.
  private static Cipher getCipher(Provider provider) throws GeneralSecurityException {
    GeneralSecurityException lastEx = null;
    for (String alias : KWP_CIPHER_ALIASES) {
      try {
        if (provider != null) {
          return Cipher.getInstance(alias, provider);
        } else {
          return Cipher.getInstance(alias);
        }
      } catch (GeneralSecurityException e) {
        lastEx = e;
      }
    }
    throw lastEx;
  }

  private static SecretKey getAesKey(int size) {
    return new SecretKeySpec(TestUtil.getRandomBytes(size), "AES");
  }
}
