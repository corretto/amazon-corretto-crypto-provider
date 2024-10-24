// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.spec.AlgorithmParameterSpec;

public class HpkeParameterSpec implements AlgorithmParameterSpec {

  // Selected ciphersuites from RFC 9180

  private static final int mode_base = 0x00;

  private static final int kem_x25519 = 0x0020;
  private static final int kem_mlkem768 = 0xff01;
  private static final int kem_mlkem1024 = 0xff02;
  private static final int kem_pqt25519 = 0xff03;
  private static final int kem_pqt256 = 0xff04;
  private static final int kem_pqt384 = 0xff05;

  private static final int kdf_hkdf_sha256 = 0x0001;
  private static final int kdf_hkdf_sha384 = 0x0002;

  private static final int aead_aes128_gcm = 0x0001;
  private static final int aead_aes256_gcm = 0x0002;
  private static final int aead_chacha20_poly1305 = 0x0003;

  /** Base mode, DHKEM-X25519, HKDF-SHA256, AES128-GCM */
  public static final HpkeParameterSpec X25519Sha256Aes128gcm =
      new HpkeParameterSpec(mode_base, kem_x25519, kdf_hkdf_sha256, aead_aes128_gcm);
  /** Base mode, DHKEM-X25519, HKDF-SHA256, ChaCha20/Poly1305 z */
  public static final HpkeParameterSpec X25519Sha256Chapoly =
      new HpkeParameterSpec(mode_base, kem_x25519, kdf_hkdf_sha256, aead_chacha20_poly1305);

  // Selected PQ and PQ/T ciphersuites (experimental)

  /** Base mode, HPKE-MLKEM768, HKDF-SHA256, AES256-GCM */
  public static final HpkeParameterSpec Mlkem768Sha256Aes256gcm =
      new HpkeParameterSpec(mode_base, kem_mlkem768, kdf_hkdf_sha256, aead_aes256_gcm);
  /** Base mode, HPKE-MLKEM1024, HKDF-SHA384, AES256-GCM */
  public static final HpkeParameterSpec Mlkem1024Sha384Aes256gcm =
      new HpkeParameterSpec(mode_base, kem_mlkem1024, kdf_hkdf_sha384, aead_aes256_gcm);

  /** Base mode, HPKE-PQT25519, HKDF-SHA256, AES256-GCM */
  public static final HpkeParameterSpec Pqt25519Sha256Aes256gcm =
      new HpkeParameterSpec(mode_base, kem_pqt25519, kdf_hkdf_sha256, aead_aes256_gcm);
  /** Base mode, HPKE-PQT256, HKDF-SHA256, AES256-GCM */
  public static final HpkeParameterSpec Pqt256Sha256Aes256gcm =
      new HpkeParameterSpec(mode_base, kem_pqt256, kdf_hkdf_sha256, aead_aes256_gcm);
  /** Base mode, HPKE-PQT384, HKDF-SHA384, AES256-GCM */
  public static final HpkeParameterSpec Pqt384Sha384Aes256gcm =
      new HpkeParameterSpec(mode_base, kem_pqt384, kdf_hkdf_sha384, aead_aes256_gcm);

  /** HPKE mode, defined in Table 1 of RFC 9180 */
  private final int mode;
  /** HPKE KEM ID, defined in Table 2 of RFC 9180 */
  private final int kemId;
  /** HPKE KDF ID, defined in Table 3 of RFC 9180 */
  private final int kdfId;
  /** HPKE AEAD ID, defined in Table 5 of RFC 9180 */
  private final int aeadId;

  private HpkeParameterSpec(int mode, int kemId, int kdfId, int aeadId) {
    this.mode = mode;
    this.kemId = kemId;
    this.kdfId = kdfId;
    this.aeadId = aeadId;
  }

  public int getMode() {
    return mode;
  }

  public int getKemId() {
    return kemId;
  }

  public int getKdfId() {
    return kdfId;
  }

  public int getAeadId() {
    return aeadId;
  }
}
