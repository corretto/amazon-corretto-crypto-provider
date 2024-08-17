// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.spec.AlgorithmParameterSpec;

public class HpkeParameterSpec implements AlgorithmParameterSpec {

  // Selected ciphersuites from RFC 9180

  // Base mode, DHKEM-X25519, HKDF-SHA256, AES128-GCM
  public static final HpkeParameterSpec X25519Sha256Aes128gcm =
      new HpkeParameterSpec(0x00, 0x0020, 0x0001, 0x0001);
  // Base mode, DHKEM-X25519, HKDF-SHA256, ChaCha20/Poly1305
  public static final HpkeParameterSpec X25519Sha256Chapoly =
      new HpkeParameterSpec(0x00, 0x0020, 0x0001, 0x0003);

  // Selected PQ and PQ/T ciphersuites (experimental)

  // Base mode, HPKE-MLKEM768, HKDF-SHA256, AES128-GCM
  public static final HpkeParameterSpec Mlkem768Sha256Aes128gcm =
      new HpkeParameterSpec(0x00, 0xff01, 0x0001, 0x0001);
  // Base mode, HPKE-MLKEM768, HKDF-SHA256, ChaCha20/Poly1305
  public static final HpkeParameterSpec Mlkem768Sha256Chapoly =
      new HpkeParameterSpec(0x00, 0xff01, 0x0001, 0x0003);
  // Base mode, HPKE-MLKEM1024, HKDF-SHA384, AES256-GCM
  public static final HpkeParameterSpec Mlkem1024Sha384Aes256gcm =
      new HpkeParameterSpec(0x00, 0xff02, 0x0002, 0x0002);

  // Base mode, HPKE-PQT25519, HKDF-SHA256, AES128-GCM
  public static final HpkeParameterSpec Pqt25519Sha256Aes128gcm =
      new HpkeParameterSpec(0x00, 0xff03, 0x0001, 0x0001);
  // Base mode, HPKE-PQT25519, HKDF-SHA256, ChaCha20/Poly1305
  public static final HpkeParameterSpec Pqt25519768Sha256Chapoly =
      new HpkeParameterSpec(0x00, 0xff03, 0x0001, 0x0003);
  // Base mode, HPKE-PQT256, HKDF-SHA256, AES128-GCM
  public static final HpkeParameterSpec Pqt256Sha256Aes128gcm =
      new HpkeParameterSpec(0x00, 0xff04, 0x0001, 0x0001);
  // Base mode, HPKE-PQT384, HKDF-SHA384, AES256-GCM
  public static final HpkeParameterSpec Pqt384Sha384Aes256gcm =
      new HpkeParameterSpec(0x00, 0xff05, 0x0002, 0x0002);

  private final int mode;
  private final int kemId;
  private final int kdfId;
  private final int aeadId;

  public HpkeParameterSpec(int mode, int kemId, int kdfId, int aeadId) {
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
