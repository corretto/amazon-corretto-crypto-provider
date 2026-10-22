// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

enum MlDsaParameter {
  // (algorithm name, NIST security level, raw public key size in bytes per FIPS 204 Table 2). The
  // level selects the NID passed to AWS-LC by MlDsaGen.generateEvpMlDsaKey.
  MLDSA_44("ML-DSA-44", 2, 1312),
  MLDSA_65("ML-DSA-65", 3, 1952),
  MLDSA_87("ML-DSA-87", 5, 2592);

  // A DER SubjectPublicKeyInfo wraps the raw ML-DSA public key in a fixed 22 bytes for every
  // parameter set: SEQUENCE header (4) + AlgorithmIdentifier with no parameters (13) + BIT STRING
  // header and unused-bits byte (5).
  private static final int SPKI_OVERHEAD = 22;

  private final String algorithmName;
  private final int level;
  private final int publicKeySize;

  MlDsaParameter(final String algorithmName, final int level, final int publicKeySize) {
    this.algorithmName = algorithmName;
    this.level = level;
    this.publicKeySize = publicKeySize;
  }

  /**
   * The parameter set whose X.509 (SubjectPublicKeyInfo) public key encoding is {@code
   * encodedLength} bytes long.
   */
  public static MlDsaParameter fromX509EncodedLength(final int encodedLength) {
    for (final MlDsaParameter candidate : values()) {
      if (candidate.publicKeySize + SPKI_OVERHEAD == encodedLength) {
        return candidate;
      }
    }
    throw new IllegalArgumentException(
        "Cannot determine ML-DSA parameter set from public key encoding length: " + encodedLength);
  }

  public String getAlgorithmName() {
    return algorithmName;
  }

  public int getLevel() {
    return level;
  }

  /** Case-insensitive match against this parameter set's JCA name. Null-safe. */
  public boolean matchesAlgorithmName(final String name) {
    return algorithmName.equalsIgnoreCase(name);
  }

  /** The parameter set whose JCA name is {@code name} (case-insensitive), or null if none. */
  public static MlDsaParameter fromAlgorithmName(final String name) {
    for (final MlDsaParameter candidate : values()) {
      if (candidate.matchesAlgorithmName(name)) {
        return candidate;
      }
    }
    return null;
  }

  /** The supported algorithm names, comma-separated, for error messages. */
  public static String supportedAlgorithmNames() {
    final StringBuilder names = new StringBuilder();
    for (final MlDsaParameter candidate : values()) {
      if (names.length() > 0) {
        names.append(", ");
      }
      names.append(candidate.getAlgorithmName());
    }
    return names.toString();
  }
}
