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
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

/** Corresponds to native constants in OpenSSL which represent keytypes. */
enum EvpKeyType {
  RSA("RSA", 6, RSAPublicKey.class, RSAPrivateKey.class),
  EC("EC", 408, ECPublicKey.class, ECPrivateKey.class),
  EdDSA("EdDSA", 949, PublicKey.class, PrivateKey.class),
  MLDSA("ML-DSA", 993, PublicKey.class, PrivateKey.class),
  MLKEM_512("ML-KEM-512", 988, PublicKey.class, PrivateKey.class),
  MLKEM_768("ML-KEM-768", 989, PublicKey.class, PrivateKey.class),
  MLKEM_1024("ML-KEM-1024", 990, PublicKey.class, PrivateKey.class);

  final String jceName;
  final int nativeValue;
  final Class<? extends PublicKey> publicKeyClass;
  final Class<? extends PrivateKey> privateKeyClass;

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
      final Class<? extends PrivateKey> privateKeyClass) {
    this.jceName = jceName;
    this.nativeValue = nativeValue;
    this.publicKeyClass = publicKeyClass;
    this.privateKeyClass = privateKeyClass;
  }

  static EvpKeyType fromJceName(final String jceName) {
    return jceNameMapping.get(jceName);
  }

  <X extends Throwable> PrivateKey buildPrivateKey(
      MiscInterfaces.ThrowingToLongBiFunction<byte[], Integer, X> fn, PKCS8EncodedKeySpec der)
      throws X {
    switch (this) {
      case RSA:
        return EvpRsaPrivateCrtKey.buildProperKey(fn.applyAsLong(der.getEncoded(), nativeValue));
      case EC:
        return new EvpEcPrivateKey(fn.applyAsLong(der.getEncoded(), nativeValue));
      case EdDSA:
        return new EvpEdPrivateKey(fn.applyAsLong(der.getEncoded(), nativeValue));
      case MLDSA:
        return new EvpMlDsaPrivateKey(fn.applyAsLong(der.getEncoded(), nativeValue));
      case MLKEM_512:
      case MLKEM_768:
      case MLKEM_1024:
        return new EvpKemPrivateKey(fn.applyAsLong(der.getEncoded(), nativeValue), this);
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
      case EdDSA:
        return new EvpEdPublicKey(fn.applyAsLong(der.getEncoded(), nativeValue));
      case MLDSA:
        return new EvpMlDsaPublicKey(fn.applyAsLong(der.getEncoded(), nativeValue));
      case MLKEM_512:
      case MLKEM_768:
      case MLKEM_1024:
        return new EvpKemPublicKey(fn.applyAsLong(der.getEncoded(), nativeValue), this);
      default:
        throw new AssertionError("Unsupported key type");
    }
  }
}
