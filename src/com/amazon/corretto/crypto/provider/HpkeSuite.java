// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.InvalidAlgorithmParameterException;

/** Supported HPKE suites and their availability and lengths in the linked AWS-LC. */
enum HpkeSuite {
  ML_KEM_768_HKDF_SHA256_AES_128_GCM(HpkeParameterSpec.ML_KEM_768_HKDF_SHA256_AES_128_GCM),
  ML_KEM_1024_HKDF_SHA384_AES_256_GCM(HpkeParameterSpec.ML_KEM_1024_HKDF_SHA384_AES_256_GCM);

  static {
    Loader.load();
  }

  static {
    // Availability comes from native capabilities, independently of build flavor, JDK version and
    // ML-KEM service registration. The main AWS-LC pin provides both suites; the FIPS pin neither.
    for (final HpkeSuite suite : values()) {
      final int[] lengths = nativeSuiteLengths(suite.kemId, suite.kdfId, suite.aeadId);
      if (lengths != null) {
        suite.available = true;
        suite.publicKeyLength = lengths[0];
        suite.privateKeyLength = lengths[1];
        suite.encLength = lengths[2];
        suite.aeadOverhead = lengths[3];
      }
    }
  }

  /** The lengths {public key, private key, enc, AEAD overhead}, or null if not provided. */
  private static native int[] nativeSuiteLengths(int kemId, int kdfId, int aeadId);

  final int kemId;
  final int kdfId;
  final int aeadId;
  private final HpkeParameterSpec spec;
  // Written once, by the static initializer above, and only for available suites.
  private boolean available;
  private int publicKeyLength;
  private int privateKeyLength;
  private int encLength;
  private int aeadOverhead;

  HpkeSuite(final HpkeParameterSpec spec) {
    this.spec = spec;
    this.kemId = spec.kem_id();
    this.kdfId = spec.kdf_id();
    this.aeadId = spec.aead_id();
  }

  boolean isAvailable() {
    return available;
  }

  HpkeParameterSpec spec() {
    return spec;
  }

  int publicKeyLength() {
    return publicKeyLength;
  }

  int privateKeyLength() {
    return privateKeyLength;
  }

  int encLength() {
    return encLength;
  }

  int aeadOverhead() {
    return aeadOverhead;
  }

  // Provider registration depends only on the linked AWS-LC's suite capabilities.
  static boolean anyAvailable() {
    for (final HpkeSuite suite : values()) {
      if (suite.available) {
        return true;
      }
    }
    return false;
  }

  /**
   * Returns the curated suite named by the ids if the linked AWS-LC provides it.
   *
   * @throws InvalidAlgorithmParameterException if the suite is not curated, or is curated but not
   *     provided by the linked AWS-LC
   */
  static HpkeSuite require(final int kemId, final int kdfId, final int aeadId)
      throws InvalidAlgorithmParameterException {
    for (final HpkeSuite suite : values()) {
      if (suite.kemId == kemId && suite.kdfId == kdfId && suite.aeadId == aeadId) {
        if (!suite.available) {
          throw new InvalidAlgorithmParameterException(
              "HPKE suite " + describe(kemId, kdfId, aeadId) + " is not available in this build");
        }
        return suite;
      }
    }
    throw new InvalidAlgorithmParameterException(
        "Unsupported HPKE suite " + describe(kemId, kdfId, aeadId));
  }

  static String describe(final int kemId, final int kdfId, final int aeadId) {
    return String.format("(kem_id=0x%04x, kdf_id=0x%04x, aead_id=0x%04x)", kemId, kdfId, aeadId);
  }
}
