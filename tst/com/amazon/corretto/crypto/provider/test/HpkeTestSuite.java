// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.NATIVE_PROVIDER;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.amazon.corretto.crypto.provider.HpkeParameterSpec;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import javax.crypto.Cipher;

/** Spec-defined lengths, kept as literals to independently check AWS-LC's reported lengths. */
enum HpkeTestSuite {
  MLKEM768(
      HpkeParameterSpec.ML_KEM_768_HKDF_SHA256_AES_128_GCM,
      "ML_KEM_768_HKDF_SHA256_AES_128_GCM",
      1184,
      64,
      1088),
  MLKEM1024(
      HpkeParameterSpec.ML_KEM_1024_HKDF_SHA384_AES_256_GCM,
      "ML_KEM_1024_HKDF_SHA384_AES_256_GCM",
      1568,
      64,
      1568);

  /** Every curated AEAD (AES-128-GCM and AES-256-GCM) has a 16-byte tag. */
  static final int AEAD_OVERHEAD = 16;

  final int kemId;
  final int kdfId;
  final int aeadId;
  final int publicKeyLength;
  final int seedLength;
  final int encLength;
  private final HpkeParameterSpec namedSpec;
  // The name of the matching constant of ACCP's package-private HpkeSuite enum.
  private final String accpName;

  HpkeTestSuite(
      final HpkeParameterSpec namedSpec,
      final String accpName,
      final int publicKeyLength,
      final int seedLength,
      final int encLength) {
    this.namedSpec = namedSpec;
    this.accpName = accpName;
    this.kemId = namedSpec.kem_id();
    this.kdfId = namedSpec.kdf_id();
    this.aeadId = namedSpec.aead_id();
    this.publicKeyLength = publicKeyLength;
    this.seedLength = seedLength;
    this.encLength = encLength;
  }

  HpkeParameterSpec spec() {
    return HpkeParameterSpec.of(kemId, kdfId, aeadId);
  }

  HpkeParameterSpec namedSpec() {
    return namedSpec;
  }

  /** ACCP's package-private {@code HpkeSuite} constant for this suite. */
  @SuppressWarnings({"unchecked", "rawtypes"})
  Object accpSuite() {
    try {
      return Enum.valueOf(
          (Class) Class.forName(TestUtil.NATIVE_PROVIDER_PACKAGE + ".HpkeSuite"), accpName);
    } catch (final ReflectiveOperationException | RuntimeException e) {
      throw new AssertionError("could not read ACCP's HPKE suite " + accpName, e);
    }
  }

  /** Fails on unreadable availability to prevent a broken probe from silently skipping tests. */
  boolean isAvailable() {
    try {
      return TestUtil.sneakyInvoke_boolean(accpSuite(), "isAvailable");
    } catch (final Throwable e) {
      throw new AssertionError("could not read ACCP's HPKE suite availability", e);
    }
  }

  static boolean anyAvailable() {
    for (final HpkeTestSuite suite : values()) {
      if (suite.isAvailable()) {
        return true;
      }
    }
    return false;
  }

  /** Gates on linked-library capability, independently of FIPS build flavor. */
  void assumeAvailable() {
    assumeTrue(isAvailable(), this + " is not provided by the AWS-LC this build links");
  }

  static HpkeTestSuite of(final int kemId, final int kdfId, final int aeadId) {
    for (final HpkeTestSuite suite : values()) {
      if (suite.kemId == kemId && suite.kdfId == kdfId && suite.aeadId == aeadId) {
        return suite;
      }
    }
    return null;
  }

  static Cipher cipher() throws GeneralSecurityException {
    return Cipher.getInstance("HPKE", NATIVE_PROVIDER);
  }

  KeyPair generateKeyPair() throws GeneralSecurityException {
    final KeyPairGenerator kpg = KeyPairGenerator.getInstance("HPKE", NATIVE_PROVIDER);
    kpg.initialize(spec());
    return kpg.generateKeyPair();
  }
}
