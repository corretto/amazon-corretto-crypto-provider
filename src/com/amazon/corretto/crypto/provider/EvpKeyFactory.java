// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

abstract class EvpKeyFactory extends KeyFactorySpi {
  private static final String PKCS8_FORMAT = "PKCS#8";
  private static final String X509_FORMAT = "X.509";
  private final EvpKeyType type;
  private final AmazonCorrettoCryptoProvider provider;

  private static native long pkcs82Evp(byte[] der, int evpType, boolean checkPrivate)
      throws InvalidKeySpecException;

  private static native long x5092Evp(byte[] der, int evpType) throws InvalidKeySpecException;

  private static native long rsa2Evp(
      byte[] modulus,
      byte[] publicExponentArr,
      byte[] privateExponentArr,
      byte[] crtCoefArr,
      byte[] expPArr,
      byte[] expQArr,
      byte[] primePArr,
      byte[] primeQArr,
      boolean checkPrivate);

  private static native long ec2Evp(
      byte[] s, byte[] wx, byte[] wy, byte[] params, boolean checkPrivate)
      throws InvalidKeySpecException;

  protected EvpKeyFactory(EvpKeyType type, AmazonCorrettoCryptoProvider provider) {
    Loader.checkNativeLibraryAvailability();
    this.type = type;
    this.provider = provider;
    if (this.type == null) {
      throw new NullPointerException("Null type?!");
    }
  }

  protected boolean shouldCheckPrivateKey() {
    return provider.hasExtraCheck(ExtraCheck.PRIVATE_KEY_CONSISTENCY);
  }

  protected long maybeCheckPkcs82Evp(byte[] der, int evpType) throws InvalidKeySpecException {
    return pkcs82Evp(der, evpType, shouldCheckPrivateKey());
  }

  @Override
  protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
    if (!(keySpec instanceof PKCS8EncodedKeySpec)) {
      throw new InvalidKeySpecException("Unsupported KeySpec");
    }
    PKCS8EncodedKeySpec pkcs8 = (PKCS8EncodedKeySpec) keySpec;

    return type.buildPrivateKey(this::maybeCheckPkcs82Evp, pkcs8);
  }

  @Override
  protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
    if (!(keySpec instanceof X509EncodedKeySpec)) {
      throw new InvalidKeySpecException("Unsupported KeySpec " + keySpec.getClass());
    }
    X509EncodedKeySpec x509 = (X509EncodedKeySpec) keySpec;

    return type.buildPublicKey(EvpKeyFactory::x5092Evp, x509);
  }

  @Override
  protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
      throws InvalidKeySpecException {
    if (keySpec.isAssignableFrom(PKCS8EncodedKeySpec.class)
        && PKCS8_FORMAT.equalsIgnoreCase(key.getFormat())) {
      return keySpec.cast(new PKCS8EncodedKeySpec(requireNonNullEncoding(key)));
    }
    if (keySpec.isAssignableFrom(X509EncodedKeySpec.class)
        && X509_FORMAT.equalsIgnoreCase(key.getFormat())) {
      return keySpec.cast(new X509EncodedKeySpec(requireNonNullEncoding(key)));
    }

    throw new InvalidKeySpecException("Unsupported KeySpec for key format");
  }

  @Override
  protected Key engineTranslateKey(Key key) throws InvalidKeyException {
    if (!keyNeedsConversion(key)) {
      return key;
    }

    try {
      final EvpKey result;
      if (PKCS8_FORMAT.equalsIgnoreCase(key.getFormat())) {
        result =
            (EvpKey) engineGeneratePrivate(new PKCS8EncodedKeySpec(requireNonNullEncoding(key)));
      } else if (X509_FORMAT.equalsIgnoreCase(key.getFormat())) {
        result = (EvpKey) engineGeneratePublic(new X509EncodedKeySpec(requireNonNullEncoding(key)));
      } else {
        throw new InvalidKeyException("Cannot convert key of format " + key.getFormat());
      }
      result.setEphemeral(true);
      return result;
    } catch (final InvalidKeySpecException ex) {
      throw new InvalidKeyException(ex);
    }
  }

  protected boolean keyNeedsConversion(Key key) throws InvalidKeyException {
    if (key.getAlgorithm() == null || !key.getAlgorithm().startsWith(type.jceName)) {
      throw new InvalidKeyException(
          "Incorrect key algorithm: " + key.getAlgorithm() + ". Expected: " + type.jceName);
    }
    return !(key instanceof EvpKey);
  }

  protected static byte[] requireNonNullEncoding(Key key) throws InvalidKeySpecException {
    final byte[] der = key.getEncoded();
    if (der == null) {
      throw new InvalidKeySpecException("Cannot convert key with NULL encoding");
    }
    return der;
  }

  protected byte[] paramsToDer(AlgorithmParameterSpec spec) {
    try {
      AlgorithmParameters params = AlgorithmParameters.getInstance(type.jceName);
      params.init(spec);
      return params.getEncoded();
    } catch (final GeneralSecurityException | IOException ex) {
      throw new AssertionError(ex);
    }
  }

  static class RSA extends EvpKeyFactory {
    RSA(AmazonCorrettoCryptoProvider provider) {
      super(EvpKeyType.RSA, provider);
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
      byte[] modulus = null;
      byte[] publicExponentArr = null;
      byte[] privateExponentArr = null;
      byte[] crtCoefArr = null;
      byte[] expPArr = null;
      byte[] expQArr = null;
      byte[] primePArr = null;
      byte[] primeQArr = null;

      if (keySpec instanceof RSAPrivateCrtKeySpec) {
        RSAPrivateCrtKeySpec spec = (RSAPrivateCrtKeySpec) keySpec;
        modulus = spec.getModulus().toByteArray();
        publicExponentArr = spec.getPublicExponent().toByteArray();
        privateExponentArr = spec.getPrivateExponent().toByteArray();
        crtCoefArr = spec.getCrtCoefficient().toByteArray();
        expPArr = spec.getPrimeExponentP().toByteArray();
        expQArr = spec.getPrimeExponentQ().toByteArray();
        primePArr = spec.getPrimeP().toByteArray();
        primeQArr = spec.getPrimeQ().toByteArray();

        return new EvpRsaPrivateCrtKey(
            rsa2Evp(
                modulus,
                publicExponentArr,
                privateExponentArr,
                crtCoefArr,
                expPArr,
                expQArr,
                primePArr,
                primeQArr,
                shouldCheckPrivateKey()));
      }
      if (keySpec instanceof RSAPrivateKeySpec) {
        RSAPrivateKeySpec spec = (RSAPrivateKeySpec) keySpec;
        modulus = spec.getModulus().toByteArray();
        privateExponentArr = spec.getPrivateExponent().toByteArray();

        return new EvpRsaPrivateKey(
            rsa2Evp(
                modulus,
                publicExponentArr,
                privateExponentArr,
                crtCoefArr,
                expPArr,
                expQArr,
                primePArr,
                primeQArr,
                shouldCheckPrivateKey()));
      }
      return super.engineGeneratePrivate(keySpec);
    }

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
      if (keySpec instanceof RSAPublicKeySpec) {
        RSAPublicKeySpec spec = (RSAPublicKeySpec) keySpec;
        byte[] modulus = spec.getModulus().toByteArray();
        byte[] publicExponentArr = spec.getPublicExponent().toByteArray();

        return new EvpRsaPublicKey(
            rsa2Evp(modulus, publicExponentArr, null, null, null, null, null, null, false));
      }
      return super.engineGeneratePublic(keySpec);
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
        throws InvalidKeySpecException {
      if (keySpec.isAssignableFrom(RSAPrivateCrtKeySpec.class) && key instanceof RSAPrivateCrtKey) {
        RSAPrivateCrtKey crtKey = (RSAPrivateCrtKey) key;
        return keySpec.cast(
            new RSAPrivateCrtKeySpec(
                crtKey.getModulus(),
                crtKey.getPublicExponent(),
                crtKey.getPrivateExponent(),
                crtKey.getPrimeP(),
                crtKey.getPrimeQ(),
                crtKey.getPrimeExponentP(),
                crtKey.getPrimeExponentQ(),
                crtKey.getCrtCoefficient()));
      }
      if (keySpec.isAssignableFrom(RSAPrivateKeySpec.class) && key instanceof RSAPrivateKey) {
        RSAPrivateKey rsaKey = (RSAPrivateKey) key;
        return keySpec.cast(
            new RSAPrivateKeySpec(rsaKey.getModulus(), rsaKey.getPrivateExponent()));
      }
      if (keySpec.isAssignableFrom(RSAPublicKeySpec.class) && key instanceof RSAPublicKey) {
        RSAPublicKey rsaKey = (RSAPublicKey) key;
        return keySpec.cast(new RSAPublicKeySpec(rsaKey.getModulus(), rsaKey.getPublicExponent()));
      }
      return super.engineGetKeySpec(key, keySpec);
    }
  }

  static class EC extends EvpKeyFactory {
    EC(AmazonCorrettoCryptoProvider provider) {
      super(EvpKeyType.EC, provider);
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
      if (keySpec instanceof ECPrivateKeySpec) {
        ECPrivateKeySpec ecSpec = (ECPrivateKeySpec) keySpec;
        return new EvpEcPrivateKey(
            ec2Evp(
                ecSpec.getS().toByteArray(),
                null,
                null,
                paramsToDer(ecSpec.getParams()),
                shouldCheckPrivateKey()));
      }
      return super.engineGeneratePrivate(keySpec);
    }

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
      if (keySpec instanceof ECPublicKeySpec) {
        ECPublicKeySpec ecSpec = (ECPublicKeySpec) keySpec;
        return new EvpEcPublicKey(
            ec2Evp(
                null,
                ecSpec.getW().getAffineX().toByteArray(),
                ecSpec.getW().getAffineY().toByteArray(),
                paramsToDer(ecSpec.getParams()),
                false));
      }
      return super.engineGeneratePublic(keySpec);
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
        throws InvalidKeySpecException {
      if (ECPublicKeySpec.class.isAssignableFrom(keySpec) && key instanceof ECPublicKey) {
        ECPublicKey ecKey = (ECPublicKey) key;
        return keySpec.cast(new ECPublicKeySpec(ecKey.getW(), ecKey.getParams()));
      }
      if (ECPrivateKeySpec.class.isAssignableFrom(keySpec) && key instanceof ECPrivateKey) {
        ECPrivateKey ecKey = (ECPrivateKey) key;
        return keySpec.cast(new ECPrivateKeySpec(ecKey.getS(), ecKey.getParams()));
      }
      return super.engineGetKeySpec(key, keySpec);
    }
  }

  private abstract static class StandardEvpKeyFactory extends EvpKeyFactory {
    StandardEvpKeyFactory(EvpKeyType type, AmazonCorrettoCryptoProvider provider) {
      super(type, provider);
    }

    @Override
    protected PrivateKey engineGeneratePrivate(final KeySpec keySpec)
        throws InvalidKeySpecException {
      return super.engineGeneratePrivate(keySpec);
    }

    @Override
    protected PublicKey engineGeneratePublic(final KeySpec keySpec) throws InvalidKeySpecException {
      return super.engineGeneratePublic(keySpec);
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(final Key key, final Class<T> keySpec)
        throws InvalidKeySpecException {
      return super.engineGetKeySpec(key, keySpec);
    }
  }

  static class EdDSA extends StandardEvpKeyFactory {
    EdDSA(AmazonCorrettoCryptoProvider provider) {
      super(EvpKeyType.EdDSA, provider);
    }
  }

  static class MLDSA extends StandardEvpKeyFactory {
    MLDSA(AmazonCorrettoCryptoProvider provider) {
      super(EvpKeyType.MLDSA, provider);
    }
  }

  static class MLKEM512 extends StandardEvpKeyFactory {
    MLKEM512(AmazonCorrettoCryptoProvider provider) {
      super(EvpKeyType.MLKEM_512, provider);
    }
  }

  static class MLKEM768 extends StandardEvpKeyFactory {
    MLKEM768(AmazonCorrettoCryptoProvider provider) {
      super(EvpKeyType.MLKEM_768, provider);
    }
  }

  static class MLKEM1024 extends StandardEvpKeyFactory {
    MLKEM1024(AmazonCorrettoCryptoProvider provider) {
      super(EvpKeyType.MLKEM_1024, provider);
    }
  }
}
