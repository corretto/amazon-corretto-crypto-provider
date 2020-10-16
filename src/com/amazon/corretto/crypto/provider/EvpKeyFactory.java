// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyFactorySpi;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.interfaces.DHPrivateKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.DHPrivateKeySpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;


abstract class EvpKeyFactory extends KeyFactorySpi {
    private final EvpKeyType type;

    private static native long pkcs82Evp(byte[] der, int nativeValue) throws InvalidKeySpecException;
    private static native long x5092Evp(byte[] der, int nativeValue) throws InvalidKeySpecException;

    private static native long rsa2Evp(byte[] modulus, byte[] publicExponentArr, byte[] privateExponentArr, byte[] crtCoefArr, byte[] expPArr, byte[] expQArr, byte[] primePArr, byte[] primeQArr);
    private static native long ec2Evp(byte[] s, byte[] wx, byte[] wy, byte[] params) throws InvalidKeySpecException; // DONE
    private static native long dsa2Evp(byte[] x, byte[] y, byte[] params);
    private static native long dh2Evp(byte[] x, byte[] y, byte[] params) throws InvalidKeySpecException; // DONE

    protected EvpKeyFactory(EvpKeyType type) {
        this.type = type;
        if (this.type == null) {
            throw new NullPointerException("Null type?!");
        }
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (!(keySpec instanceof PKCS8EncodedKeySpec)) {
            throw new InvalidKeySpecException("Unsupported KeySpec");
        }
        PKCS8EncodedKeySpec pkcs8 = (PKCS8EncodedKeySpec) keySpec;

        return type.buildPrivateKey(EvpKeyFactory::pkcs82Evp, pkcs8);
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
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
        if (keySpec.isAssignableFrom(PKCS8EncodedKeySpec.class) && key.getFormat().equalsIgnoreCase("PKCS#8")) {
            return keySpec.cast(new PKCS8EncodedKeySpec(requireNonNullEncoding(key)));
        }
        if (keySpec.isAssignableFrom(X509EncodedKeySpec.class) && key.getFormat().equalsIgnoreCase("X.509")) {
            return keySpec.cast(new X509EncodedKeySpec(requireNonNullEncoding(key)));
        }

        throw new InvalidKeySpecException("Unsupported KeySpec for key format");
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        // Caller must have already called keyNeedsConversion!
        try {
            final EvpKey result;
            if (key.getFormat().equalsIgnoreCase("PKCS#8")) {
                result = (EvpKey) engineGeneratePrivate(new PKCS8EncodedKeySpec(requireNonNullEncoding(key)));
            } else if (key.getFormat().equalsIgnoreCase("X.509")) {
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
        if (!type.jceName.equalsIgnoreCase(key.getAlgorithm())) {
            throw new InvalidKeyException("Incorrect key algorithm: " + key.getAlgorithm());
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
        RSA() {
            super(EvpKeyType.RSA);
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

                return new EvpRsaPrivateCrtKey(rsa2Evp(modulus, publicExponentArr, privateExponentArr, crtCoefArr, expPArr, expQArr, primePArr, primeQArr));
            }
            if (keySpec instanceof RSAPrivateKeySpec) {
                RSAPrivateKeySpec spec = (RSAPrivateKeySpec) keySpec;
                modulus = spec.getModulus().toByteArray();
                privateExponentArr = spec.getPrivateExponent().toByteArray();

                return new EvpRsaPrivateKey(rsa2Evp(modulus, publicExponentArr, privateExponentArr, crtCoefArr, expPArr, expQArr, primePArr, primeQArr));
            }
            return super.engineGeneratePrivate(keySpec);
        }

        @Override
        protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
            if (keySpec instanceof RSAPublicKeySpec) {
                RSAPublicKeySpec spec = (RSAPublicKeySpec) keySpec;
                byte[] modulus = spec.getModulus().toByteArray();
                byte[] publicExponentArr = spec.getPublicExponent().toByteArray();

                return new EvpRsaPublicKey(rsa2Evp(modulus, publicExponentArr, null, null, null, null, null, null));
            }
            return super.engineGeneratePublic(keySpec);
        }

        @Override
        protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
            if (keySpec.isAssignableFrom(RSAPrivateCrtKeySpec.class) && key instanceof RSAPrivateCrtKey) {
                RSAPrivateCrtKey crtKey = (RSAPrivateCrtKey) key;
                return keySpec.cast(new RSAPrivateCrtKeySpec(
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
                return keySpec.cast(new RSAPrivateKeySpec(rsaKey.getModulus(), rsaKey.getPrivateExponent()));
            }
            if (keySpec.isAssignableFrom(RSAPublicKeySpec.class) && key instanceof RSAPublicKey) {
                RSAPublicKey rsaKey = (RSAPublicKey) key;
                return keySpec.cast(new RSAPublicKeySpec(rsaKey.getModulus(), rsaKey.getPublicExponent()));
            }
            return super.engineGetKeySpec(key, keySpec);
        }

        @Override
        protected Key engineTranslateKey(Key key) throws InvalidKeyException {
            if (!keyNeedsConversion(key)) {
                return key;
            }
            // TODO: Do we need special logic?
            return super.engineTranslateKey(key);
        }
    }

    static class EC extends EvpKeyFactory {
        EC() {
            super(EvpKeyType.EC);
        }

        @Override
        protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
            if (keySpec instanceof ECPrivateKeySpec) {
                ECPrivateKeySpec ecSpec = (ECPrivateKeySpec) keySpec;
                return new EvpEcPrivateKey(ec2Evp(ecSpec.getS().toByteArray(), null, null, paramsToDer(ecSpec.getParams())));
            }
            return super.engineGeneratePrivate(keySpec);
        }

        @Override
        protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
            if (keySpec instanceof ECPublicKeySpec) {
                ECPublicKeySpec ecSpec = (ECPublicKeySpec) keySpec;
                return new EvpEcPublicKey(ec2Evp(null,
                    ecSpec.getW().getAffineX().toByteArray(), ecSpec.getW().getAffineY().toByteArray(),
                    paramsToDer(ecSpec.getParams())));
            }
            return super.engineGeneratePublic(keySpec);
        }

        @Override
        protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
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

        @Override
        protected Key engineTranslateKey(Key key) throws InvalidKeyException {
            if (!keyNeedsConversion(key)) {
                return key;
            }
            // TODO: Do we need special logic?
            return super.engineTranslateKey(key);
        }
    }

    static class DH extends EvpKeyFactory {
        DH() {
            super(EvpKeyType.DH);
        }

        @Override
        protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
            if (keySpec instanceof DHPrivateKeySpec) {
                DHPrivateKeySpec dhSpec = (DHPrivateKeySpec) keySpec;
                return new EvpDhPrivateKey(dh2Evp(dhSpec.getX().toByteArray(), null, paramsToDer(new DHParameterSpec(dhSpec.getP(), dhSpec.getG()))));
            }
            return super.engineGeneratePrivate(keySpec);
        }

        @Override
        protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
            if (keySpec instanceof DHPublicKeySpec) {
                DHPublicKeySpec dhSpec = (DHPublicKeySpec) keySpec;
                return new EvpDhPublicKey(dh2Evp(null, dhSpec.getY().toByteArray(),
                    paramsToDer(new DHParameterSpec(dhSpec.getP(), dhSpec.getG()))));
            }
            return super.engineGeneratePublic(keySpec);
        }

        @Override
        @SuppressWarnings("unchecked")
        protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
            if (DHPublicKeySpec.class.isAssignableFrom(keySpec) && key instanceof DHPublicKey) {
                DHPublicKey dhKey = (DHPublicKey) key;
                DHParameterSpec params = dhKey.getParams();
                return keySpec.cast(new DHPublicKeySpec(dhKey.getY(), params.getP(), params.getG()));
            }
            if (DHPrivateKeySpec.class.isAssignableFrom(keySpec) && key instanceof DHPrivateKey) {
                DHPrivateKey dhKey = (DHPrivateKey) key;
                DHParameterSpec params = dhKey.getParams();
                return keySpec.cast(new DHPrivateKeySpec(dhKey.getX(), params.getP(), params.getG()));
            }
            return super.engineGetKeySpec(key, keySpec);
        }

        @Override
        protected Key engineTranslateKey(Key key) throws InvalidKeyException {
            if (!keyNeedsConversion(key)) {
                return key;
            }
            // TODO: Do we need special logic?
            return super.engineTranslateKey(key);
        }
    }

    static class DSA extends EvpKeyFactory {
        DSA() {
            super(EvpKeyType.DSA);
        }

        @Override
        protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
            if (keySpec instanceof DSAPrivateKeySpec) {
                DSAPrivateKeySpec dsaSpec = (DSAPrivateKeySpec) keySpec;
                return new EvpDsaPrivateKey(dsa2Evp(dsaSpec.getX().toByteArray(), null,
                    paramsToDer(new DSAParameterSpec(dsaSpec.getP(), dsaSpec.getQ(), dsaSpec.getG()))));
            }
            return super.engineGeneratePrivate(keySpec);
        }

        @Override
        protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
            if (keySpec instanceof DSAPublicKeySpec) {
                DSAPublicKeySpec dsaSpec = (DSAPublicKeySpec) keySpec;
                return new EvpDsaPublicKey(dsa2Evp(null, dsaSpec.getY().toByteArray(),
                    paramsToDer(new DSAParameterSpec(dsaSpec.getP(), dsaSpec.getQ(), dsaSpec.getG()))));
            }
            return super.engineGeneratePublic(keySpec);
        }

        @Override
        @SuppressWarnings("unchecked")
        protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
            if (DSAPublicKeySpec.class.isAssignableFrom(keySpec) && key instanceof DSAPublicKey) {
                DSAPublicKey dsaKey = (DSAPublicKey) key;
                DSAParams params = dsaKey.getParams();
                return keySpec.cast(new DSAPublicKeySpec(dsaKey.getY(), params.getP(), params.getQ(), params.getG()));
            }
            if (DSAPrivateKeySpec.class.isAssignableFrom(keySpec) && key instanceof DSAPrivateKey) {
                DSAPrivateKey dsaKey = (DSAPrivateKey) key;
                DSAParams params = dsaKey.getParams();
                return keySpec.cast(new DSAPrivateKeySpec(dsaKey.getX(), params.getP(), params.getQ(), params.getG()));
            }
            return super.engineGetKeySpec(key, keySpec);
        }

        @Override
        protected Key engineTranslateKey(Key key) throws InvalidKeyException {
            if (!keyNeedsConversion(key)) {
                return key;
            }
            // TODO: Do we need special logic?
            return super.engineTranslateKey(key);
        }
    }

    // This next block of code is a micro-optimization around getting instances of this factory.
    // It turns out the KeyFactory.getInstance(String, Provider) can be expensive
    // (primarily due to synchronization of Provider.getService).
    // The JDK tries to speed up the fast-path by remembering the last service retrieved
    // for a given Provider and returning it quickly if it is retrieved again.
    //
    // With the move to EVP keys many of our SPIs require an instance of KeyFactory that they can
    // use (primarily for translateKey). Since this means that retrieving a non-KeyFactory SPI
    // shortly thereafter results in retrieving a KeyFactory SPI, there is real churn in
    // Provider.getService which can massively slow-down performance.
    //
    // These methods will do a lazy-init (to avoid circular dependencies) of minimal KeyFactories
    // for ACCP use only. This way we only create one of each and do not touch the expensive
    // Provider.getService logic.
    static KeyFactory commonRsaFactory() {
        return FieldHolder.RSA_FACTORY;
    }

    static KeyFactory commonDsaFactory() {
        return FieldHolder.DSA_FACTORY;
    }

    static KeyFactory commonDhFactory() {
        return FieldHolder.DH_FACTORY;
    }

    static KeyFactory commonEcFactory() {
        return FieldHolder.EC_FACTORY;
    }

    // Lazy-initialization of fields without needing to worry about synchronization
    private static class FieldHolder {
        static final KeyFactory RSA_FACTORY = new ShimFactory(new RSA());
        static final KeyFactory DSA_FACTORY = new ShimFactory(new DSA());
        static final KeyFactory DH_FACTORY = new ShimFactory(new DH());
        static final KeyFactory EC_FACTORY = new ShimFactory(new EC());
    }

    /**
     * Minimal KeyFactory used by the lazily initialized keyfactories above for internal use.
     */
    private static class ShimFactory extends KeyFactory {
        private ShimFactory(EvpKeyFactory spi) {
            super(spi, AmazonCorrettoCryptoProvider.INSTANCE, spi.type.jceName);
        }
    }
}
