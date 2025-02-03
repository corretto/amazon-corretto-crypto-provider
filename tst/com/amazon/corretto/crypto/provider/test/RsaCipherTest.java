// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.NATIVE_PROVIDER;
import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static com.amazon.corretto.crypto.provider.test.TestUtil.assumeMinimumVersion;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyConstruct;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyInvoke_int;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
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
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
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
public class RsaCipherTest {
  private static final String OAEP_SHA1_PADDING = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
  // Some non-JCA-standard aliases are allowed for compatibility
  private static final String OAEP_SHA1_PADDING_ALT1 = "RSA/ECB/OAEPWithSHA1AndMGF1Padding";
  private static final String OAEP_PADDING = "RSA/ECB/OAEPPadding";
  private static final String PKCS1_PADDING = "RSA/ECB/Pkcs1Padding";
  private static final String NO_PADDING = "RSA/ECB/NoPadding";
  private static final KeyPairGenerator JCE_KEY_GEN;
  private static final KeyFactory JCE_KEY_FACTORY;
  private static final KeyPair PAIR_1024;
  private static final KeyPair PAIR_2048;
  private static final KeyPair PAIR_4096;
  private static final KeyPair PAIR_512;

  static {
    try {
      JCE_KEY_FACTORY = KeyFactory.getInstance("RSA");
      JCE_KEY_GEN = KeyPairGenerator.getInstance("RSA");
      JCE_KEY_GEN.initialize(1024);
      PAIR_1024 = JCE_KEY_GEN.generateKeyPair();
      JCE_KEY_GEN.initialize(2048);
      PAIR_2048 = JCE_KEY_GEN.generateKeyPair();
      JCE_KEY_GEN.initialize(4096);
      PAIR_4096 = JCE_KEY_GEN.generateKeyPair();
      JCE_KEY_GEN.initialize(512);
      PAIR_512 = JCE_KEY_GEN.generateKeyPair();
    } catch (final GeneralSecurityException ex) {
      throw new AssertionError(ex);
    }
  }

  public static List<String> paddingParams() {
    return Arrays.asList(
        OAEP_PADDING, OAEP_SHA1_PADDING, OAEP_SHA1_PADDING_ALT1, PKCS1_PADDING, NO_PADDING);
  }

  public static List<String> messageDigestParams() {
    List<String> digests = new ArrayList<>();
    try {
      for (Field f : MGF1ParameterSpec.class.getDeclaredFields()) {
        if (Modifier.isStatic(f.getModifiers())
            && f.getType().isAssignableFrom(MGF1ParameterSpec.class)) {
          Object o = f.get(null); // static field, so null "instance"
          Method m = MGF1ParameterSpec.class.getDeclaredMethod("getDigestAlgorithm");
          String digest = (String) m.invoke(o);
          // NOTE: AWS-LC doesn't support SHA-512/224 or SHA3 in a recent FIPS
          //       version, but does support them as of non-FIPS v1.17.0
          if ("SHA-512/224".equals(digest) || !digest.startsWith("SHA-")) {
            continue;
          }
          digests.add(digest);
        }
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
    return digests;
  }

  public static List<Integer> lengthParams() {
    return Arrays.asList(512, 1024, 2048, 4096);
  }

  public static List<Arguments> paddingXlengthParams() {
    final List<Arguments> result = new ArrayList<>();
    for (String padding : paddingParams()) {
      for (Integer length : lengthParams()) {
        result.add(Arguments.of(padding, length, null, ""));
      }
    }
    for (Integer length : lengthParams()) {
      for (String primaryMd : messageDigestParams()) {
        for (String mgf1Md : messageDigestParams()) {
          final OAEPParameterSpec oaep =
              new OAEPParameterSpec(
                  primaryMd, "MGF1", new MGF1ParameterSpec(mgf1Md), PSource.PSpecified.DEFAULT);
          final int paddingSize = getPaddingSize(OAEP_PADDING, oaep);
          final int keySize = (length + 7) / 8;
          // The padding size must not exceed key size
          if (keySize >= paddingSize) {
            result.add(
                Arguments.of(
                    OAEP_PADDING, length, oaep, String.format("(%s, %s)", primaryMd, mgf1Md)));
          }
        }
      }
    }
    return result;
  }

  private static byte[] getPlaintext(final int size) {
    final byte[] result = new byte[size];
    Arrays.fill(result, (byte) 0x55);
    return result;
  }

  private static Cipher getNativeCipher(final String padding) throws GeneralSecurityException {
    return Cipher.getInstance(padding, NATIVE_PROVIDER);
  }

  private static Cipher getJceCipher(final String padding) throws GeneralSecurityException {
    final Cipher result = Cipher.getInstance(padding);
    assertFalse(result.getProvider().getName().equals(NATIVE_PROVIDER.getName()));
    return result;
  }

  @ParameterizedTest
  @MethodSource("paddingXlengthParams")
  public void testOffsetPlaintext(
      final String padding,
      final Integer keySize,
      final OAEPParameterSpec oaep,
      final String ignoredName)
      throws Exception {
    assumeFalse(NO_PADDING.equalsIgnoreCase(padding), "Only valid with padding");

    final byte[] plaintext = new byte[(keySize / 8) - getPaddingSize(padding, oaep)];
    ThreadLocalRandom.current().nextBytes(plaintext);

    final KeyPair keyPair = getKeyPair(keySize);
    Cipher cipher = getNativeCipher(padding);
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic(), oaep);
    byte[] ciphertext = cipher.doFinal(plaintext, 1, plaintext.length - 1);

    cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate(), oaep);

    byte[] result = new byte[cipher.getOutputSize(ciphertext.length) + 2];
    int resultLen = cipher.doFinal(ciphertext, 0, ciphertext.length, result, 2);

    assertArrayEquals(
        Arrays.copyOfRange(plaintext, 1, plaintext.length),
        Arrays.copyOfRange(result, 2, 2 + resultLen));
  }

  @ParameterizedTest
  @MethodSource("paddingXlengthParams")
  public void testOffsetCiphertext(
      final String padding,
      final Integer keySize,
      final OAEPParameterSpec oaep,
      final String ignoredName)
      throws Exception {
    assumeFalse(NO_PADDING.equalsIgnoreCase(padding), "Only valid with padding");

    final byte[] plaintext = new byte[(keySize / 8) - getPaddingSize(padding, oaep)];
    ThreadLocalRandom.current().nextBytes(plaintext);

    final KeyPair keyPair = getKeyPair(keySize);
    Cipher cipher = getNativeCipher(padding);
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic(), oaep);
    byte[] ciphertext = new byte[cipher.getOutputSize(plaintext.length) + 2];
    int ciphertextLen = cipher.doFinal(plaintext, 0, plaintext.length, ciphertext, 1);

    // Shift the ciphertext over before reading
    System.arraycopy(ciphertext, 1, ciphertext, 2, ciphertext.length - 2);

    cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate(), oaep);

    byte[] result = cipher.doFinal(ciphertext, 2, ciphertextLen);

    assertArrayEquals(plaintext, result);
  }

  @ParameterizedTest
  @MethodSource("paddingXlengthParams")
  public void native2jce(
      final String padding,
      final Integer keySize,
      final OAEPParameterSpec oaep,
      final String ignoredName)
      throws GeneralSecurityException {
    testNative2Jce(padding, keySize, oaep);
  }

  @ParameterizedTest
  @MethodSource("paddingXlengthParams")
  public void jce2Native(
      final String padding,
      final Integer keySize,
      final OAEPParameterSpec oaep,
      final String ignoredName)
      throws GeneralSecurityException {
    testJce2Native(padding, keySize, oaep);
  }

  private void assertProperWrongInputSizeException(GeneralSecurityException ex)
      throws GeneralSecurityException {
    // Behavior changed as of version 1.5.0 and sometimes we need tests to run
    // against older versions.
    if (TestUtil.versionCompare("1.5.0", NATIVE_PROVIDER) <= 0) {
      if (!(ex instanceof IllegalBlockSizeException)) {
        throw ex;
      }
    } else {
      if (!(ex instanceof BadPaddingException)) {
        throw ex;
      }
    }
  }

  @ParameterizedTest
  @MethodSource("lengthParams")
  public void noPaddingSizes(final Integer keySize) throws GeneralSecurityException {
    final Cipher nativeEncrypt = getNativeCipher(NO_PADDING);
    nativeEncrypt.init(Cipher.ENCRYPT_MODE, getKeyPair(keySize).getPublic());

    byte[] plaintext = new byte[keySize / 8];
    Arrays.fill(plaintext, (byte) 0xff);
    try {
      nativeEncrypt.doFinal(plaintext);
      fail("Expected bad padding exception");
    } catch (final BadPaddingException ex) {
      // expected
    }
  }

  @ParameterizedTest
  @MethodSource("paddingXlengthParams")
  public void overlargeCiphertext(
      final String padding,
      final Integer keySize,
      final OAEPParameterSpec oaep,
      final String ignoredName)
      throws GeneralSecurityException {
    final Cipher nativeEncrypt = getNativeCipher(padding);
    nativeEncrypt.init(Cipher.DECRYPT_MODE, getKeyPair(keySize).getPrivate(), oaep);

    byte[] ciphertext = new byte[(keySize / 8) + 1];
    Arrays.fill(ciphertext, (byte) 1); // All zeroes isn't a valid ciphertext
    assertThrows(IllegalBlockSizeException.class, () -> nativeEncrypt.doFinal(ciphertext));
  }

  @Test
  public void oaepParamValidation() throws GeneralSecurityException {
    Cipher c = getNativeCipher(OAEP_PADDING);
    final OAEPParameterSpec spec = OAEPParameterSpec.DEFAULT; // SHA-1 for everything

    c.init(Cipher.ENCRYPT_MODE, PAIR_2048.getPublic(), spec);

    // Empty psource (should still work)
    PSource psource = new PSource.PSpecified(new byte[0]);
    final OAEPParameterSpec emptySource =
        new OAEPParameterSpec(
            OAEPParameterSpec.DEFAULT.getDigestAlgorithm(),
            OAEPParameterSpec.DEFAULT.getMGFAlgorithm(),
            OAEPParameterSpec.DEFAULT.getMGFParameters(),
            psource);
    c.init(Cipher.ENCRYPT_MODE, PAIR_2048.getPublic(), emptySource);

    // Fake MGF
    final OAEPParameterSpec badMgf =
        new OAEPParameterSpec(
            OAEPParameterSpec.DEFAULT.getDigestAlgorithm(),
            "FakeMGF",
            OAEPParameterSpec.DEFAULT.getMGFParameters(),
            OAEPParameterSpec.DEFAULT.getPSource());
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> c.init(Cipher.ENCRYPT_MODE, PAIR_2048.getPublic(), badMgf));

    // Non-empty PSource
    psource = new PSource.PSpecified(new byte[1]);
    final OAEPParameterSpec badSource =
        new OAEPParameterSpec(
            OAEPParameterSpec.DEFAULT.getDigestAlgorithm(),
            OAEPParameterSpec.DEFAULT.getMGFAlgorithm(),
            OAEPParameterSpec.DEFAULT.getMGFParameters(),
            psource);
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> c.init(Cipher.ENCRYPT_MODE, PAIR_2048.getPublic(), badSource));

    // Bad message digest parameters
    final OAEPParameterSpec badMd =
        new OAEPParameterSpec(
            "nonsense",
            OAEPParameterSpec.DEFAULT.getMGFAlgorithm(),
            OAEPParameterSpec.DEFAULT.getMGFParameters(),
            OAEPParameterSpec.DEFAULT.getPSource());
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> c.init(Cipher.ENCRYPT_MODE, PAIR_2048.getPublic(), badMd));
    final OAEPParameterSpec badMgfMd =
        new OAEPParameterSpec(
            OAEPParameterSpec.DEFAULT.getDigestAlgorithm(),
            OAEPParameterSpec.DEFAULT.getMGFAlgorithm(),
            new MGF1ParameterSpec("nonsense"),
            OAEPParameterSpec.DEFAULT.getPSource());
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> c.init(Cipher.ENCRYPT_MODE, PAIR_2048.getPublic(), badMgfMd));
    final OAEPParameterSpec md5Md =
        new OAEPParameterSpec(
            "MD-5",
            OAEPParameterSpec.DEFAULT.getMGFAlgorithm(),
            OAEPParameterSpec.DEFAULT.getMGFParameters(),
            OAEPParameterSpec.DEFAULT.getPSource());
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> c.init(Cipher.ENCRYPT_MODE, PAIR_2048.getPublic(), md5Md));
    final OAEPParameterSpec md4Md =
        new OAEPParameterSpec(
            "MD-4",
            OAEPParameterSpec.DEFAULT.getMGFAlgorithm(),
            OAEPParameterSpec.DEFAULT.getMGFParameters(),
            OAEPParameterSpec.DEFAULT.getPSource());
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> c.init(Cipher.ENCRYPT_MODE, PAIR_2048.getPublic(), md4Md));

    // SHA1 + MGF1 + SHA1 is the only supported String parameter, need to use OAEPParameterSpec in
    // init(...) to specify other digest algorithms.
    String sha256ParamString = OAEP_SHA1_PADDING.replace("SHA-1", "SHA-256");
    assertThrows(NoSuchAlgorithmException.class, () -> getNativeCipher(sha256ParamString));
  }

  @Test
  public void modifyOaepParameterSpec() throws GeneralSecurityException {
    // General OAEP: Correct default
    Cipher c = getNativeCipher(OAEP_PADDING);
    OAEPParameterSpec params = c.getParameters().getParameterSpec(OAEPParameterSpec.class);
    assertOAEPParamSpecsEqual(OAEPParameterSpec.DEFAULT, params);

    // General OAEP: Update with default is still default
    c.init(Cipher.ENCRYPT_MODE, PAIR_2048.getPublic(), OAEPParameterSpec.DEFAULT);
    params = c.getParameters().getParameterSpec(OAEPParameterSpec.class);
    assertOAEPParamSpecsEqual(OAEPParameterSpec.DEFAULT, params);

    // General OAEP: Ensure that different digest configurations persist
    for (String digest : messageDigestParams()) {
      final OAEPParameterSpec newParams =
          new OAEPParameterSpec(
              digest,
              OAEPParameterSpec.DEFAULT.getMGFAlgorithm(),
              OAEPParameterSpec.DEFAULT.getMGFParameters(),
              OAEPParameterSpec.DEFAULT.getPSource());
      c.init(Cipher.ENCRYPT_MODE, PAIR_2048.getPublic(), newParams);
      params = c.getParameters().getParameterSpec(OAEPParameterSpec.class);
      assertOAEPParamSpecsEqual(newParams, params);
    }

    // OAEP SHA1: Correct default
    final Cipher c2 = getNativeCipher(OAEP_SHA1_PADDING);
    params = c2.getParameters().getParameterSpec(OAEPParameterSpec.class);
    assertOAEPParamSpecsEqual(OAEPParameterSpec.DEFAULT, params);

    // OAEP SHA1: Update with default is OK and still default
    c2.init(Cipher.ENCRYPT_MODE, PAIR_2048.getPublic(), OAEPParameterSpec.DEFAULT);
    params = c2.getParameters().getParameterSpec(OAEPParameterSpec.class);
    assertOAEPParamSpecsEqual(OAEPParameterSpec.DEFAULT, params);

    // OAEP SHA1: If params were specified on Cipehr.getInstance, then trying to
    //            specify different parameters on Cipher.init should throw.
    final OAEPParameterSpec sha256Params =
        new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
    TestUtil.assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> c2.init(Cipher.ENCRYPT_MODE, PAIR_2048.getPublic(), sha256Params));
  }

  @ParameterizedTest
  @MethodSource("lengthParams")
  public void noPaddingShortPlaintexts(final Integer keySize) throws GeneralSecurityException {
    // We actually expect short plaintexts to be left zero padded.
    // This is acceptable because RSA just handles numbers internally
    // and adding zero-bytes to the left doesn't change the values.

    final Cipher nativeEncrypt = getNativeCipher(NO_PADDING);
    final Cipher nativeDecrypt = getNativeCipher(NO_PADDING);
    final KeyPair keyPair = getKeyPair(keySize);
    nativeEncrypt.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
    nativeDecrypt.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

    byte[] plaintext = getPlaintext(keySize / 8 - 1);
    byte[] ciphertext = nativeEncrypt.doFinal(plaintext);
    byte[] decrypted = nativeDecrypt.doFinal(ciphertext);
    assertArrayEquals(trimLeftZeros(plaintext), trimLeftZeros(decrypted));

    plaintext = getPlaintext(keySize / 8 - 10);
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

  @ParameterizedTest
  @MethodSource("lengthParams")
  public void native2JcePkcs1Padding(final Integer keySize) throws GeneralSecurityException {
    assumeMinimumVersion("1.0.1", NATIVE_PROVIDER);
    final Cipher nativeC = getNativeCipher(PKCS1_PADDING);
    final Cipher jceC = getJceCipher(PKCS1_PADDING);
    final byte[] plaintext = getPlaintext((keySize / 8) - getPaddingSize(PKCS1_PADDING, null));

    final KeyPair keyPair = getKeyPair(keySize);
    nativeC.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
    final byte[] ciphertext = nativeC.doFinal(plaintext);

    jceC.init(Cipher.DECRYPT_MODE, keyPair.getPublic());
    assertArrayEquals(plaintext, jceC.doFinal(ciphertext));
  }

  @ParameterizedTest
  @MethodSource("lengthParams")
  public void jce2NativePkcs1PaddingReversedKeys(final Integer keySize)
      throws GeneralSecurityException {
    assumeMinimumVersion("1.0.1", NATIVE_PROVIDER);
    final Cipher nativeC = getNativeCipher(PKCS1_PADDING);
    final Cipher jceC = getJceCipher(PKCS1_PADDING);
    final byte[] plaintext = getPlaintext((keySize / 8) - getPaddingSize(PKCS1_PADDING, null));

    final KeyPair keyPair = getKeyPair(keySize);
    jceC.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
    final byte[] ciphertext = jceC.doFinal(plaintext);

    nativeC.init(Cipher.DECRYPT_MODE, keyPair.getPublic());
    assertArrayEquals(plaintext, nativeC.doFinal(ciphertext));
  }

  @ParameterizedTest
  @MethodSource("lengthParams")
  public void native2JceNoPaddingReversedKeys(final Integer keySize)
      throws GeneralSecurityException {
    assumeMinimumVersion("1.0.1", NATIVE_PROVIDER);
    final Cipher nativeC = getNativeCipher(NO_PADDING);
    final Cipher jceC = getJceCipher(NO_PADDING);
    final byte[] plaintext = getPlaintext(keySize / 8);

    final KeyPair keyPair = getKeyPair(keySize);
    nativeC.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
    final byte[] ciphertext = nativeC.doFinal(plaintext);

    jceC.init(Cipher.DECRYPT_MODE, keyPair.getPublic());
    assertArrayEquals(plaintext, jceC.doFinal(ciphertext));
  }

  @ParameterizedTest
  @MethodSource("lengthParams")
  public void jce2NativeNoPaddingReversedKeys(final Integer keySize)
      throws GeneralSecurityException {
    assumeMinimumVersion("1.0.1", NATIVE_PROVIDER);
    final Cipher nativeC = getNativeCipher(NO_PADDING);
    final Cipher jceC = getJceCipher(NO_PADDING);
    final byte[] plaintext = getPlaintext(keySize / 8);

    final KeyPair keyPair = getKeyPair(keySize);
    jceC.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
    final byte[] ciphertext = jceC.doFinal(plaintext);

    nativeC.init(Cipher.DECRYPT_MODE, keyPair.getPublic());
    assertArrayEquals(plaintext, nativeC.doFinal(ciphertext));
  }

  @ParameterizedTest
  @MethodSource("paddingXlengthParams")
  public void paddingSizes(
      final String padding,
      final Integer keySize,
      final OAEPParameterSpec oaep,
      final String ignoredName)
      throws GeneralSecurityException {
    final Cipher nativeC = getNativeCipher(padding);
    nativeC.init(Cipher.ENCRYPT_MODE, getKeyPair(keySize).getPublic(), oaep);

    byte[] plaintext = getPlaintext((keySize / 8) - getPaddingSize(padding, oaep) + 1);
    try {
      nativeC.doFinal(plaintext);
      fail("Expected IllegalBlockSizeException");
    } catch (final GeneralSecurityException ex) {
      assertProperWrongInputSizeException(ex);
    }
  }

  @ParameterizedTest
  @MethodSource("paddingXlengthParams")
  public void native2jce_parts(
      final String padding,
      final Integer keySize,
      final OAEPParameterSpec oaep,
      final String ignoredName)
      throws GeneralSecurityException {
    final Cipher jceC = Cipher.getInstance(padding);
    final Cipher nativeC = getNativeCipher(padding);

    final byte[] plaintext = getPlaintext((keySize / 8) - getPaddingSize(padding, oaep));
    final KeyPair keyPair = getKeyPair(keySize);
    nativeC.init(Cipher.ENCRYPT_MODE, keyPair.getPublic(), oaep);
    jceC.init(Cipher.DECRYPT_MODE, keyPair.getPrivate(), oaep);

    nativeC.update(plaintext, 0, plaintext.length / 2);
    nativeC.update(plaintext, plaintext.length / 2, plaintext.length - (plaintext.length / 2));
    final byte[] ciphertext = nativeC.doFinal();
    final byte[] decrypted = jceC.doFinal(ciphertext);
    assertArrayEquals(plaintext, decrypted);
  }

  @ParameterizedTest
  @MethodSource("paddingXlengthParams")
  public void native2jce_parts2(
      final String padding,
      final Integer keySize,
      final OAEPParameterSpec oaep,
      final String ignoredName)
      throws GeneralSecurityException {
    final Cipher jceC = Cipher.getInstance(padding);
    final Cipher nativeC = getNativeCipher(padding);

    final byte[] plaintext = getPlaintext((keySize / 8) - getPaddingSize(padding, oaep));
    final KeyPair keyPair = getKeyPair(keySize);
    nativeC.init(Cipher.ENCRYPT_MODE, keyPair.getPublic(), oaep);
    jceC.init(Cipher.DECRYPT_MODE, keyPair.getPrivate(), oaep);

    nativeC.update(plaintext, 0, plaintext.length / 2);
    nativeC.update(plaintext, plaintext.length / 2, plaintext.length - (plaintext.length / 2) - 1);
    final byte[] ciphertext = nativeC.doFinal(plaintext, plaintext.length - 1, 1);
    final byte[] decrypted = jceC.doFinal(ciphertext);
    assertArrayEquals(plaintext, decrypted);
  }

  @ParameterizedTest
  @MethodSource("paddingXlengthParams")
  public void noCrt(
      final String padding,
      final Integer keySize,
      final OAEPParameterSpec oaep,
      final String ignoredName)
      throws GeneralSecurityException {
    final KeyPair keyPair = getKeyPair(keySize);
    // Strip out the CRT factors
    final RSAPrivateKey prvKey = (RSAPrivateKey) keyPair.getPrivate();
    final PrivateKey strippedKey =
        JCE_KEY_FACTORY.generatePrivate(
            new RSAPrivateKeySpec(prvKey.getModulus(), prvKey.getPrivateExponent()));

    final Cipher enc = getNativeCipher(padding);
    final Cipher dec = getNativeCipher(padding);

    final byte[] plaintext = getPlaintext(keySize / 8 - getPaddingSize(padding, oaep));
    enc.init(Cipher.ENCRYPT_MODE, keyPair.getPublic(), oaep);
    dec.init(Cipher.DECRYPT_MODE, strippedKey, oaep);

    final byte[] ciphertext = enc.doFinal(plaintext);
    final byte[] decrypted = dec.doFinal(ciphertext);
    assertArrayEquals(plaintext, decrypted);
  }

  @ParameterizedTest
  @MethodSource("paddingXlengthParams")
  public void badCrt(
      final String padding,
      final Integer keySize,
      final OAEPParameterSpec oaep,
      final String ignoredName)
      throws GeneralSecurityException {
    final KeyPair keyPair = getKeyPair(keySize);
    // Corrupt out the CRT factors
    final RSAPrivateCrtKeySpec goodSpec =
        JCE_KEY_FACTORY.getKeySpec(keyPair.getPrivate(), RSAPrivateCrtKeySpec.class);
    final RSAPrivateCrtKeySpec badSpec =
        new RSAPrivateCrtKeySpec(
            goodSpec.getModulus(),
            goodSpec.getPublicExponent(),
            goodSpec.getPrivateExponent(),
            goodSpec.getPrimeP(),
            goodSpec.getPrimeQ(),
            goodSpec.getPrimeP(),
            goodSpec.getPrimeExponentQ().add(BigInteger.ONE),
            goodSpec.getCrtCoefficient());
    final PrivateKey privateKey = JCE_KEY_FACTORY.generatePrivate(badSpec);

    final Cipher cipher = getNativeCipher(padding);

    TestUtil.assertThrows(
        InvalidKeyException.class, () -> cipher.init(Cipher.DECRYPT_MODE, privateKey, oaep));
  }

  @ParameterizedTest
  @MethodSource("paddingXlengthParams")
  public void smallOutputBuffer(
      final String padding,
      final Integer keySize,
      final OAEPParameterSpec oaep,
      final String ignoredName)
      throws GeneralSecurityException {
    final Cipher enc = getNativeCipher(padding);
    final Cipher dec = getNativeCipher(padding);

    final byte[] plaintext = getPlaintext((keySize / 8) - getPaddingSize(padding, oaep));
    final KeyPair keyPair = getKeyPair(keySize);
    enc.init(Cipher.ENCRYPT_MODE, keyPair.getPublic(), oaep);
    dec.init(Cipher.DECRYPT_MODE, keyPair.getPrivate(), oaep);

    final byte[] output = new byte[(keySize / 8) - 1];
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

  @ParameterizedTest
  @MethodSource("paddingXlengthParams")
  public void noninitialized(
      final String padding,
      final Integer keySize,
      final OAEPParameterSpec oaep,
      final String ignoredName)
      throws GeneralSecurityException {
    final Cipher enc = getNativeCipher(padding);
    final byte[] plaintext = getPlaintext((keySize / 8) - getPaddingSize(padding, oaep));
    assertThrows(IllegalStateException.class, () -> enc.doFinal(plaintext));
  }

  @ParameterizedTest
  @MethodSource("lengthParams")
  public void native2jceOaepParams(final Integer keySize) throws GeneralSecurityException {
    final Cipher nativeC = getNativeCipher(OAEP_PADDING);
    // NOTE: asserting here that nativeC has proper default params
    final AlgorithmParameters params = nativeC.getParameters();
    assertNotNull(params);
    assertEquals("OAEP", params.getAlgorithm());
    final Cipher jceC = Cipher.getInstance(OAEP_PADDING);
    final KeyPair keyPair = getKeyPair(keySize);
    nativeC.init(Cipher.ENCRYPT_MODE, keyPair.getPublic(), params);
    jceC.init(Cipher.DECRYPT_MODE, keyPair.getPrivate(), params);

    final int paddingSize =
        getPaddingSize(OAEP_PADDING, params.getParameterSpec(OAEPParameterSpec.class));
    final byte[] plaintext = getPlaintext(keySize / 8 - paddingSize);

    final byte[] ciphertext = nativeC.doFinal(plaintext);
    final byte[] decrypted = jceC.doFinal(ciphertext);
    assertArrayEquals(plaintext, decrypted);
  }

  @ParameterizedTest
  @MethodSource("paddingParams")
  public void testSetOaepParamsOnNonOaepPadding(final String padding)
      throws GeneralSecurityException {
    assumeFalse(padding.contains("OAEP"), "Only testing non-OAEP padding");
    final Cipher cipher = getNativeCipher(padding);
    KeyPair kp = getKeyPair(2048);
    TestUtil.assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic(), OAEPParameterSpec.DEFAULT));
    TestUtil.assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> cipher.init(Cipher.DECRYPT_MODE, kp.getPrivate(), OAEPParameterSpec.DEFAULT));
  }

  // Inspect each field, as for some reason the OAEPParameterSpec.equals method seems
  // to compare object hash code instead of individual members.
  private static void assertOAEPParamSpecsEqual(OAEPParameterSpec a, OAEPParameterSpec b) {
    assertEquals(
        a.getDigestAlgorithm().replaceAll("-", ""), b.getDigestAlgorithm().replaceAll("-", ""));
    assertEquals(a.getMGFAlgorithm(), b.getMGFAlgorithm());
    assertEquals(a.getMGFParameters(), b.getMGFParameters());
    assertEquals(a.getPSource().getAlgorithm(), b.getPSource().getAlgorithm());
  }

  @ParameterizedTest
  @MethodSource("paddingXlengthParams")
  public void wrapAes(
      final String padding,
      final Integer keySize,
      final OAEPParameterSpec oaep,
      final String ignoredName)
      throws GeneralSecurityException {
    assumeFalse(
        NO_PADDING.equalsIgnoreCase(padding),
        "Padding is necessary to know where the wrapped key ends");
    final Cipher wrap = getNativeCipher(padding);
    final Cipher unwrap = getNativeCipher(padding);

    wrapUnwrapAes(keySize, wrap, unwrap);
  }

  @ParameterizedTest
  @MethodSource("paddingXlengthParams")
  public void jce2nativeWrapAes(
      final String padding,
      final Integer keySize,
      final OAEPParameterSpec oaep,
      final String ignoredName)
      throws GeneralSecurityException {
    assumeFalse(
        NO_PADDING.equalsIgnoreCase(padding),
        "Padding is necessary to know where the wrapped key ends");
    final Cipher jceC = getJceCipher(padding);
    final Cipher nativeC = getNativeCipher(padding);

    wrapUnwrapAes(keySize, jceC, nativeC);
  }

  @ParameterizedTest
  @MethodSource("paddingXlengthParams")
  public void native2JceWrapAes(
      final String padding,
      final Integer keySize,
      final OAEPParameterSpec oaep,
      final String ignoredName)
      throws GeneralSecurityException {
    assumeFalse(
        NO_PADDING.equalsIgnoreCase(padding),
        "Padding is necessary to know where the wrapped key ends");
    final Cipher jceC = getJceCipher(padding);
    final Cipher nativeC = getNativeCipher(padding);

    wrapUnwrapAes(keySize, nativeC, jceC);
  }

  private void wrapUnwrapAes(final Integer keySize, final Cipher encryptor, final Cipher decryptor)
      throws InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException {
    final byte[] rawKey = TestUtil.getRandomBytes(16);
    final SecretKeySpec original = new SecretKeySpec(rawKey, "AES");
    final KeyPair keyPair = getKeyPair(keySize);
    encryptor.init(Cipher.WRAP_MODE, keyPair.getPublic());
    decryptor.init(Cipher.UNWRAP_MODE, keyPair.getPrivate());

    final SecretKey unwrapped =
        (SecretKey) decryptor.unwrap(encryptor.wrap(original), "AES", Cipher.SECRET_KEY);
    assertEquals(original.getAlgorithm(), unwrapped.getAlgorithm());
    assertArrayEquals(original.getEncoded(), unwrapped.getEncoded());
  }

  @ParameterizedTest
  @MethodSource("paddingParams")
  public void jce2nativeWrapRsa(final String padding) throws GeneralSecurityException {
    assumeFalse(
        NO_PADDING.equalsIgnoreCase(padding),
        "Padding is necessary to know where the wrapped key ends");
    final Cipher jceC = getJceCipher(padding);
    final Cipher nativeC = getNativeCipher(padding);
    wrapUnwrapRsa(jceC, nativeC);
  }

  @ParameterizedTest
  @MethodSource("paddingParams")
  public void native2JceWrapRsa(final String padding) throws GeneralSecurityException {
    assumeFalse(
        NO_PADDING.equalsIgnoreCase(padding),
        "Padding is necessary to know where the wrapped key ends");
    final Cipher jceC = getJceCipher(padding);
    final Cipher nativeC = getNativeCipher(padding);
    wrapUnwrapRsa(nativeC, jceC);
  }

  @ParameterizedTest
  @MethodSource("paddingXlengthParams")
  public void badPaddingTooSmall(
      final String padding,
      final Integer keySize,
      final OAEPParameterSpec oaep,
      final String ignoredName)
      throws Exception {
    assumeFalse(NO_PADDING.equalsIgnoreCase(padding), "Only valid with padding");
    final Cipher enc = Cipher.getInstance(NO_PADDING, NATIVE_PROVIDER);
    final KeyPair keyPair = getKeyPair(keySize);
    enc.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
    final byte[] plaintext = new byte[512 / 8];
    plaintext[plaintext.length - 1] = 2;
    final byte[] ciphertext = enc.doFinal(plaintext);
    final Cipher dec = getNativeCipher(padding);
    dec.init(Cipher.DECRYPT_MODE, keyPair.getPrivate(), oaep);
    assertThrows(BadPaddingException.class, () -> dec.doFinal(ciphertext));
  }

  @ParameterizedTest
  @MethodSource("paddingXlengthParams")
  public void badPaddingTooBig(
      final String padding,
      final Integer keySize,
      final OAEPParameterSpec oaep,
      final String ignoredName)
      throws Exception {
    assumeFalse(NO_PADDING.equalsIgnoreCase(padding), "Only valid with padding");
    final Cipher enc = Cipher.getInstance(NO_PADDING, NATIVE_PROVIDER);
    final KeyPair keyPair = getKeyPair(keySize);
    enc.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
    final byte[] plaintext = new byte[keySize / 8];
    Arrays.fill(plaintext, (byte) 1);
    byte[] ciphertext = enc.doFinal(plaintext);
    final Cipher dec = getNativeCipher(padding);
    dec.init(Cipher.DECRYPT_MODE, keyPair.getPrivate(), oaep);
    assertThrows(BadPaddingException.class, () -> dec.doFinal(ciphertext));
  }

  // Unlike padded modes which have an upper-plaintext size defined in bytes,
  // NoPadding has an upper-plaintext size defined numerically as the value of
  // the modulus. So, we have a special test case for that.
  @Test
  public void slightlyOverlargePlaintextNoPadding() throws Exception {
    final Cipher enc = Cipher.getInstance(NO_PADDING, NATIVE_PROVIDER);
    enc.init(Cipher.ENCRYPT_MODE, PAIR_2048.getPublic());
    byte[] plaintext = ((RSAPublicKey) PAIR_2048.getPublic()).getModulus().toByteArray();
    // Strip leading zero sign bit/byte if present
    if (plaintext[0] == 0) {
      plaintext = Arrays.copyOfRange(plaintext, 1, plaintext.length);
    }
    final byte[] tmp = plaintext;
    assertThrows(BadPaddingException.class, () -> enc.doFinal(tmp));
  }

  @ParameterizedTest
  @MethodSource("paddingXlengthParams")
  public void slightlyOverlargeCiphertext(
      final String padding,
      final Integer keySize,
      final OAEPParameterSpec oaep,
      final String ignoredName)
      throws Exception {
    final Cipher dec = getNativeCipher(padding);
    final KeyPair keyPair = getKeyPair(keySize);
    dec.init(Cipher.DECRYPT_MODE, keyPair.getPrivate(), oaep);
    byte[] plaintext = ((RSAPublicKey) keyPair.getPublic()).getModulus().toByteArray();
    // Strip leading zero sign bit/byte if present
    if (plaintext[0] == 0) {
      plaintext = Arrays.copyOfRange(plaintext, 1, plaintext.length);
    }
    final byte[] tmp = plaintext;
    assertThrows(BadPaddingException.class, () -> dec.doFinal(tmp));
  }

  @ParameterizedTest
  @MethodSource("lengthParams")
  public void engineGetKeySize(final Integer keySize) throws Throwable {
    final KeyPair keyPair = getKeyPair(keySize);
    final Object cipherSpi =
        sneakyConstruct(TestUtil.NATIVE_PROVIDER_PACKAGE + ".RsaCipher$Pkcs1", NATIVE_PROVIDER);
    assertEquals(keySize, sneakyInvoke_int(cipherSpi, "engineGetKeySize", keyPair.getPublic()));
    assertEquals(keySize, sneakyInvoke_int(cipherSpi, "engineGetKeySize", keyPair.getPrivate()));
  }

  @ParameterizedTest
  @MethodSource("paddingParams")
  public void nullIV(final String padding) throws GeneralSecurityException {
    final Cipher dec = getNativeCipher(padding);
    // Init because on symmetric ciphers this forces creation of an IV
    dec.init(Cipher.DECRYPT_MODE, PAIR_2048.getPrivate());
    assertEquals(null, dec.getIV());
  }

  @ParameterizedTest
  @MethodSource("paddingParams")
  public void zeroBlockSize(final String padding) throws GeneralSecurityException {
    final Cipher dec = getNativeCipher(padding);
    // Init because asymmetric ciphers work in blocks of the key size despite always returning 0 (as
    // per the JCE spec)
    dec.init(Cipher.DECRYPT_MODE, PAIR_2048.getPrivate());
    assertEquals(0, dec.getBlockSize());
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
      threads.add(new TestThread("RsaCipherThread-" + x, rng, iterations, OAEP_SHA1_PADDING, keys));
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

  @Test
  public void noInputDoFinal() throws Exception {
    assumeMinimumVersion("1.6.0", NATIVE_PROVIDER);
    final Cipher enc = Cipher.getInstance(NO_PADDING, NATIVE_PROVIDER);
    enc.init(Cipher.ENCRYPT_MODE, PAIR_1024.getPublic());
    final byte[] result = enc.doFinal();
    for (final byte b : result) {
      assertEquals(b, 0);
    }
  }

  private void testNative2Jce(final String padding, final int keySize, final OAEPParameterSpec oaep)
      throws GeneralSecurityException {
    final Cipher jceC = getJceCipher(padding);
    final Cipher nativeC = getNativeCipher(padding);

    testEncryptDecryptCycle(jceC, nativeC, padding, keySize, oaep);
  }

  private void testJce2Native(final String padding, final int keySize, final OAEPParameterSpec oaep)
      throws GeneralSecurityException {
    final Cipher jceC = getJceCipher(padding);
    final Cipher nativeC = getNativeCipher(padding);

    testEncryptDecryptCycle(nativeC, jceC, padding, keySize, oaep);
  }

  private void testEncryptDecryptCycle(
      final Cipher encrypt,
      final Cipher decrypt,
      final String padding,
      final int keySize,
      final OAEPParameterSpec oaep)
      throws GeneralSecurityException {
    final int paddingSize = getPaddingSize(padding, oaep);

    final byte[] plaintext = getPlaintext((keySize / 8) - paddingSize);

    final KeyPair pair = getKeyPair(keySize);

    encrypt.init(Cipher.ENCRYPT_MODE, pair.getPublic(), oaep);
    decrypt.init(Cipher.DECRYPT_MODE, pair.getPrivate(), oaep);

    // verify that the OAEPParameterSpec is set properly.
    if (oaep != null) {
      assertOAEPParamSpecsEqual(
          oaep, encrypt.getParameters().getParameterSpec(OAEPParameterSpec.class));
      assertOAEPParamSpecsEqual(
          oaep, decrypt.getParameters().getParameterSpec(OAEPParameterSpec.class));
    } else if (padding.contains("OAEP")) {
      assertOAEPParamSpecsEqual(
          OAEPParameterSpec.DEFAULT,
          encrypt.getParameters().getParameterSpec(OAEPParameterSpec.class));
      assertOAEPParamSpecsEqual(
          OAEPParameterSpec.DEFAULT,
          decrypt.getParameters().getParameterSpec(OAEPParameterSpec.class));
    } else {
      assertNull(encrypt.getParameters());
      assertNull(decrypt.getParameters());
    }

    final byte[] ciphertext = encrypt.doFinal(plaintext);
    final byte[] decrypted = decrypt.doFinal(ciphertext);
    assertArrayEquals(plaintext, decrypted);

    // Test otherwised missed lines for a specific update case
    assertEquals(0, decrypt.update(ciphertext, 0, ciphertext.length / 2, new byte[0], 0));
    assertEquals(
        0,
        decrypt.update(
            ciphertext,
            ciphertext.length / 2,
            ciphertext.length - (ciphertext.length / 2),
            new byte[0],
            0));
    assertArrayEquals(plaintext, decrypt.doFinal());

    // Verify no release of data even on bad padding
    if (!NO_PADDING.equals(padding)) {
      final byte[] result = new byte[ciphertext.length]; // Full size
      ciphertext[3] ^= 0x13; // Just twiddle some bits
      assertThrows(
          BadPaddingException.class,
          () -> decrypt.doFinal(ciphertext, 0, ciphertext.length, result, 0));
      assertArrayEquals(new byte[ciphertext.length], result);

      Arrays.fill(result, (byte) 0);
      ByteBuffer ciphertextBuff = ByteBuffer.wrap(ciphertext);
      ByteBuffer resultBuff = ByteBuffer.wrap(result);
      assertThrows(BadPaddingException.class, () -> decrypt.doFinal(ciphertextBuff, resultBuff));
      assertArrayEquals(new byte[ciphertext.length], result);
    }
  }

  private static int getPaddingSize(final String padding, final OAEPParameterSpec oaep) {
    if (oaep == null) {
      switch (padding) {
        case NO_PADDING:
          return 0;
        case PKCS1_PADDING:
          return 11;
        case OAEP_PADDING:
        case OAEP_SHA1_PADDING:
        case OAEP_SHA1_PADDING_ALT1:
          return 42;
        default:
          throw new IllegalArgumentException("Bad padding: " + padding);
      }
    } else {
      final String md = oaep.getDigestAlgorithm();
      assertTrue(md.startsWith("SHA")); // JCE only supports SHA digests for OAEP
      final int mdSize;
      if (md.startsWith("SHA-1")) {
        mdSize = 20; // 20 bytes == 160 bits
      } else {
        Matcher m = Pattern.compile("[\\d]+$").matcher(md);
        assertTrue(m.find());
        mdSize = (Integer.parseInt(m.group()) + 7) / 8;
      }
      return 2 * mdSize + 2;
    }
  }

  private KeyPair getKeyPair(final int keySize) {
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
    return pair;
  }

  private void wrapUnwrapRsa(final Cipher wrap, final Cipher unwrap)
      throws InvalidKeyException, IllegalBlockSizeException, NoSuchAlgorithmException {
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

    public TestThread(
        final String name,
        final SecureRandom rng,
        final int iterations,
        final String transformation,
        final List<KeyPair> keys)
        throws GeneralSecurityException {
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
