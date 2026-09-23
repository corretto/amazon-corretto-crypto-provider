// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.NATIVE_PROVIDER;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.InvalidKeyException;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.stream.Stream;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Contracts that hold for every AES Cipher name ACCP registers: an {@code AES_<n>} Standard Name
 * accepts only the key size it names, and a Cipher initialized without a caller-supplied {@link
 * SecureRandom} still gets a random IV.
 *
 * <p>The cases come from the provider's own service list, so a newly registered AES name is covered
 * without touching this test.
 */
@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class AesCipherContractTest {
  // A whole number of blocks, so the padded and unpadded modes both accept it.
  private static final byte[] PLAINTEXT = TestUtil.getRandomBytes(64);
  private static final int[] AES_KEY_SIZES = new int[] {16, 24, 32};
  private static final int UNPINNED_KEY_SIZE = 16;

  /** Names that pin a key size, paired with the size in bytes. */
  static Stream<Arguments> pinnedKeySizeNames() {
    return aesCipherNames()
        .filter(name -> pinnedKeySize(name) != 0)
        .map(name -> Arguments.of(transformation(name), pinnedKeySize(name)));
  }

  /** Names whose Cipher derives its own IV at initialization, paired with a usable key size. */
  static Stream<Arguments> ivGeneratingNames() {
    return aesCipherNames()
        .filter(name -> Arrays.asList("CBC", "CFB", "CTR", "GCM").contains(mode(name)))
        .map(
            name ->
                Arguments.of(
                    transformation(name),
                    pinnedKeySize(name) == 0 ? UNPINNED_KEY_SIZE : pinnedKeySize(name)));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("pinnedKeySizeNames")
  public void pinnedNameAcceptsOnlyItsOwnKeySize(final String transformation, final int pinnedSize)
      throws Exception {
    for (final int keySize : AES_KEY_SIZES) {
      final Cipher cipher = Cipher.getInstance(transformation, NATIVE_PROVIDER);
      final SecretKey key = new SecretKeySpec(TestUtil.getRandomBytes(keySize), "AES");
      if (keySize == pinnedSize) {
        cipher.init(Cipher.ENCRYPT_MODE, key);
        assertRoundTrip(transformation, key, cipher);
      } else {
        assertThrows(InvalidKeyException.class, () -> cipher.init(Cipher.ENCRYPT_MODE, key));
      }
    }
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("ivGeneratingNames")
  public void initWithoutSecureRandomStillGetsRandomIv(
      final String transformation, final int keySize) throws Exception {
    final SecretKey key = new SecretKeySpec(TestUtil.getRandomBytes(keySize), "AES");

    final Cipher cipher = Cipher.getInstance(transformation, NATIVE_PROVIDER);
    cipher.init(Cipher.ENCRYPT_MODE, key, (SecureRandom) null);
    assertNotNull(cipher.getIV(), "no IV was generated");

    final Cipher second = Cipher.getInstance(transformation, NATIVE_PROVIDER);
    second.init(Cipher.ENCRYPT_MODE, key, (SecureRandom) null);
    assertFalse(Arrays.equals(cipher.getIV(), second.getIV()), "IV repeated across inits");

    assertRoundTrip(transformation, key, cipher);
  }

  /** Decrypts what an initialized Cipher produces, reusing the parameters it chose. */
  private static void assertRoundTrip(
      final String transformation, final SecretKey key, final Cipher encrypt) throws Exception {
    final byte[] ciphertext = encrypt.doFinal(PLAINTEXT);
    final Cipher decrypt = Cipher.getInstance(transformation, NATIVE_PROVIDER);
    decrypt.init(Cipher.DECRYPT_MODE, key, encrypt.getParameters());
    assertArrayEquals(PLAINTEXT, decrypt.doFinal(ciphertext));
  }

  private static Stream<String> aesCipherNames() {
    return NATIVE_PROVIDER.getServices().stream()
        .filter(service -> "Cipher".equals(service.getType()))
        .map(Provider.Service::getAlgorithm)
        .filter(name -> name.startsWith("AES"));
  }

  /** Key size in bytes named by an {@code AES_<n>} prefix, or 0 when the name pins no size. */
  private static int pinnedKeySize(final String name) {
    if (!name.startsWith("AES_")) {
      return 0;
    }
    return Integer.parseInt(name.substring(4, name.indexOf('/'))) / 8;
  }

  private static String mode(final String name) {
    final String[] parts = name.split("/");
    return parts.length > 1 ? parts[1] : "";
  }

  /** Cipher.getInstance rejects a two-part transformation, so supply the missing padding. */
  private static String transformation(final String name) {
    return name.split("/").length == 3 ? name : name + "/NoPadding";
  }
}
