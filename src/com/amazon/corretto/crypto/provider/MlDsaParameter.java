// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

enum MlDsaParameter {
  // (algorithm name, NIST security level). The level selects the NID passed to AWS-LC by
  // MlDsaGen.generateEvpMlDsaKey.
  MLDSA_44("ML-DSA-44", 2),
  MLDSA_65("ML-DSA-65", 3),
  MLDSA_87("ML-DSA-87", 5);

  private final String algorithmName;
  private final int level;

  MlDsaParameter(final String algorithmName, final int level) {
    this.algorithmName = algorithmName;
    this.level = level;
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
