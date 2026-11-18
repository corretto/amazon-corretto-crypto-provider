// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/** Corresponds to native constants in OpenSSL which represent keytypes. */
enum EvpKeyType {
  RSA("RSA", 6, RSAPublicKey.class, RSAPrivateKey.class),
  EC("EC", 408, ECPublicKey.class, ECPrivateKey.class),
  // X25519 is the curve-specific name for the single XDH curve ACCP implements, and the provider
  // registers its services under both names. A key carrying either name is the same key, so both
  // are accepted here. X448 is deliberately absent: it is an XDH curve ACCP does not implement, and
  // rejecting it is what lets the JCA fall through to a provider that does.
  XDH("XDH", 948, PublicKey.class, PrivateKey.class, "X25519"),
  EdDSA("EdDSA", 949, PublicKey.class, PrivateKey.class),
  MLDSA("ML-DSA", 993, PublicKey.class, PrivateKey.class),
  MLKEM("ML-KEM", 970, PublicKey.class, PrivateKey.class);

  final String jceName;
  final int nativeValue;
  final Class<? extends PublicKey> publicKeyClass;
  final Class<? extends PrivateKey> privateKeyClass;
  private final Set<String> alternateJceNames;

  private static final Map<String, EvpKeyType> jceNameMapping = new HashMap<>();

  static {
    for (final EvpKeyType type : EnumSet.allOf(EvpKeyType.class)) {
      jceNameMapping.put(type.jceName, type);
    }
  }

  private EvpKeyType(
      final String jceName,
      final int nativeValue,
      final Class<? extends PublicKey> publicKeyClass,
      final Class<? extends PrivateKey> privateKeyClass,
      final String... alternateJceNames) {
    this.jceName = jceName;
    this.nativeValue = nativeValue;
    this.publicKeyClass = publicKeyClass;
    this.privateKeyClass = privateKeyClass;
    this.alternateJceNames =
        Collections.unmodifiableSet(new HashSet<>(Arrays.asList(alternateJceNames)));
  }

  static EvpKeyType fromJceName(final String jceName) {
    return jceNameMapping.get(jceName);
  }

  /**
   * Whether {@code algorithm} names this key type. The primary name is matched as a prefix, since
   * the parameterized types spell their parameter set as a suffix ("ML-KEM-512" for "ML-KEM"). An
   * alternate name is a complete algorithm name rather than the head of a family, so it is matched
   * exactly and never extends to another algorithm that happens to begin with it.
   */
  boolean matchesAlgorithm(final String algorithm) {
    return algorithm != null
        && (algorithm.startsWith(jceName) || alternateJceNames.contains(algorithm));
  }

  <X extends Throwable> PrivateKey buildPrivateKey(
      MiscInterfaces.ThrowingToLongBiFunction<byte[], Integer, X> fn, PKCS8EncodedKeySpec der)
      throws X {
    switch (this) {
      case RSA:
        return EvpRsaPrivateCrtKey.buildProperKey(fn.applyAsLong(der.getEncoded(), nativeValue));
      case EC:
        return new EvpEcPrivateKey(fn.applyAsLong(der.getEncoded(), nativeValue));
      case XDH:
        return new EvpXECPrivateKey(fn.applyAsLong(der.getEncoded(), nativeValue));
      case EdDSA:
        return new EvpEdPrivateKey(fn.applyAsLong(der.getEncoded(), nativeValue));
      case MLDSA:
        return new EvpMlDsaPrivateKey(fn.applyAsLong(der.getEncoded(), nativeValue));
      case MLKEM:
        return new EvpKemPrivateKey(fn.applyAsLong(der.getEncoded(), nativeValue));
      default:
        throw new AssertionError("Unsupported key type");
    }
  }

  <X extends Throwable> PublicKey buildPublicKey(
      MiscInterfaces.ThrowingToLongBiFunction<byte[], Integer, X> fn, X509EncodedKeySpec der)
      throws X {
    switch (this) {
      case RSA:
        return new EvpRsaPublicKey(fn.applyAsLong(der.getEncoded(), nativeValue));
      case EC:
        return new EvpEcPublicKey(fn.applyAsLong(der.getEncoded(), nativeValue));
      case XDH:
        return new EvpXECPublicKey(fn.applyAsLong(der.getEncoded(), nativeValue));
      case EdDSA:
        return new EvpEdPublicKey(fn.applyAsLong(der.getEncoded(), nativeValue));
      case MLDSA:
        return new EvpMlDsaPublicKey(fn.applyAsLong(der.getEncoded(), nativeValue));
      case MLKEM:
        return new EvpKemPublicKey(fn.applyAsLong(der.getEncoded(), nativeValue));
      default:
        throw new AssertionError("Unsupported key type");
    }
  }
}
