// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.utils;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import com.amazon.corretto.crypto.provider.HpkeParameterSpec;
import com.amazon.corretto.crypto.provider.HpkePrivateKey;
import com.amazon.corretto.crypto.provider.HpkePublicKey;
import com.amazon.corretto.crypto.provider.RuntimeCryptoException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;

/** Public utility methods for single-message HPKE base-mode encryption and decryption. */
public final class HpkeUtils {
  private static final String DECRYPTION_FAILED = "HPKE decryption failed";

  private HpkeUtils() {}

  /**
   * Encrypts {@code plaintext} to {@code recipient} and returns {@code enc || ct} in one exactly
   * sized array of {@code recipient.encapsulationLength() + plaintext.length + 16} bytes.
   *
   * <p>Selects ACCP regardless of provider order and creates a fresh HPKE context with one message
   * at sequence number 0. The key selects the suite. The first {@link
   * com.amazon.corretto.crypto.provider.HpkeKey#encapsulationLength()} bytes are the encapsulation;
   * the rest is the AEAD ciphertext, including its 16-byte tag.
   *
   * <p>Null or empty {@code info} and {@code aad} mean empty. Use {@code info} to bind context.
   *
   * @param recipient the recipient's public key; also selects the suite
   * @param info the HPKE {@code info}, or null for empty
   * @param aad the additional authenticated data, or null for empty
   * @param plaintext the message
   * @return the encapsulation followed by the ciphertext
   * @throws IllegalArgumentException if {@code recipient} or {@code plaintext} is null
   * @throws InvalidKeyException if AWS-LC rejects the public key
   */
  public static byte[] seal(
      final HpkePublicKey recipient, final byte[] info, final byte[] aad, final byte[] plaintext)
      throws InvalidKeyException {
    if (recipient == null) {
      throw new IllegalArgumentException("recipient must not be null");
    }
    if (plaintext == null) {
      throw new IllegalArgumentException("plaintext must not be null");
    }
    try {
      final Cipher cipher = newCipher();
      cipher.init(Cipher.ENCRYPT_MODE, recipient, spec(recipient.parameterSpec(), info));
      final byte[] enc = cipher.getIV();
      final byte[] out = new byte[enc.length + cipher.getOutputSize(plaintext.length)];
      System.arraycopy(enc, 0, out, 0, enc.length);
      if (aad != null && aad.length != 0) {
        cipher.updateAAD(aad);
      }
      final int written = cipher.doFinal(plaintext, 0, plaintext.length, out, enc.length);
      if (enc.length + written != out.length) {
        throw new RuntimeCryptoException("Unexpected HPKE output length");
      }
      return out;
    } catch (final InvalidKeyException ex) {
      throw ex;
    } catch (final GeneralSecurityException ex) {
      // The key's own suite is always available and the output is exactly sized.
      throw new RuntimeCryptoException("Unexpected HPKE failure", ex);
    }
  }

  /**
   * Decrypts {@code enc || ct} as produced by {@link #seal} for {@code recipient}'s public key.
   *
   * <p>Selects ACCP regardless of provider order and opens one message at sequence number 0 in a
   * fresh HPKE context. The key selects the suite and the encapsulation length; the remaining bytes
   * are the AEAD ciphertext, including its 16-byte tag. Null or empty {@code info} and {@code aad}
   * mean empty.
   *
   * <p>Encapsulation and authentication failures, including truncated input, wrong {@code info} or
   * {@code aad}, and modified ciphertext, throw {@link AEADBadTagException} with the message {@code
   * "HPKE decryption failed"}.
   *
   * @param recipient the recipient's private key; also selects the suite
   * @param info the HPKE {@code info}, or null for empty
   * @param aad the additional authenticated data, or null for empty
   * @param encAndCt the encapsulation followed by the ciphertext
   * @return the plaintext
   * @throws IllegalArgumentException if {@code recipient} or {@code encAndCt} is null
   * @throws InvalidKeyException if {@code recipient} has been destroyed
   * @throws AEADBadTagException with message {@code "HPKE decryption failed"} if {@code encAndCt}
   *     does not open
   */
  public static byte[] open(
      final HpkePrivateKey recipient, final byte[] info, final byte[] aad, final byte[] encAndCt)
      throws InvalidKeyException, AEADBadTagException {
    if (recipient == null) {
      throw new IllegalArgumentException("recipient must not be null");
    }
    if (encAndCt == null) {
      throw new IllegalArgumentException("encAndCt must not be null");
    }
    final int encLength = recipient.encapsulationLength();
    if (encAndCt.length < encLength) {
      throw new AEADBadTagException(DECRYPTION_FAILED);
    }
    try {
      final Cipher cipher = newCipher();
      final byte[] enc = Arrays.copyOfRange(encAndCt, 0, encLength);
      cipher.init(
          Cipher.DECRYPT_MODE,
          recipient,
          spec(recipient.parameterSpec(), info).withEncapsulation(enc));
      if (aad != null && aad.length != 0) {
        cipher.updateAAD(aad);
      }
      return cipher.doFinal(encAndCt, encLength, encAndCt.length - encLength);
    } catch (final InvalidAlgorithmParameterException | BadPaddingException ex) {
      // Normalize encapsulation and AEAD failures without identifying the rejected part.
      throw new AEADBadTagException(DECRYPTION_FAILED);
    } catch (final InvalidKeyException ex) {
      throw ex;
    } catch (final GeneralSecurityException ex) {
      throw new RuntimeCryptoException("Unexpected HPKE failure", ex);
    }
  }

  private static Cipher newCipher() throws GeneralSecurityException {
    // Fresh contexts keep calls independent and safe across threads.
    return Cipher.getInstance("HPKE", AmazonCorrettoCryptoProvider.INSTANCE);
  }

  private static HpkeParameterSpec spec(final HpkeParameterSpec suite, final byte[] info) {
    // withInfo rejects an empty info, which is already the default.
    return info == null || info.length == 0 ? suite : suite.withInfo(info);
  }
}
