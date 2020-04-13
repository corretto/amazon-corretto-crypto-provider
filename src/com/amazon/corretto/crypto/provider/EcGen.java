// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

import com.amazon.corretto.crypto.provider.EcUtils.ECInfo;
import com.amazon.corretto.crypto.provider.EcUtils.NativeGroup;

class EcGen extends KeyPairGeneratorSpi {
    private static final ECGenParameterSpec DEFAULT_SPEC = new ECGenParameterSpec("secp384r1");
    private static final ConcurrentHashMap<ECInfo, ThreadLocal<NativeParams>> PARAM_CACHE = new ConcurrentHashMap<>();
    private static final Function<ECInfo, ThreadLocal<NativeParams>> CACHE_LOADER = t -> {
            return new ThreadLocal<EcGen.NativeParams>() {
                @Override
                protected NativeParams initialValue() {
                    return new NativeParams(buildEcParams(t.nid));
                }
            };
    };

    private static native long buildEcParams(int nid);
    private static native void freeEcParams(long ptr);

    /**
     * Generates a new EC key and returns it in {@code x}, {@code y}, and {@code s}.
     *
     * @param params
     *            a native pointer created by {@link #buildEcParams(int)}
     * @param curve
     *            a native pointer returned by {@link ECInfo#groupPtr()}
     * @param checkConsistency
     *            Run additional consistency checks on the generated keypair
     * @param x
     *            an array which will hold the returned BigInteger value. Must be sufficiently long.
     * @param y
     *            an array which will hold the returned BigInteger value. Must be sufficiently long.
     * @param s
     *            an array which will hold the returned BigInteger value. Must be sufficiently long.
     */
    private static native void generateEcKey(long params, long curve, boolean checkConsistency, byte[] x, byte[] y, byte[] s);

    /**
     * Generates a new EC key and returns it in {@code x}, {@code y}, and {@code s}.
     *
     * @param spec
     *            an ASN.1 encoded {@link ECParameterSpec}
     * @param checkConsistency
     *            Run additional consistency checks on the generated keypair
     * @param x
     *            an array which will hold the returned BigInteger value. Must be sufficiently long.
     * @param y
     *            an array which will hold the returned BigInteger value. Must be sufficiently long.
     * @param s
     *            an array which will hold the returned BigInteger value. Must be sufficiently long.
     */
    private static native void generateEcKeyFromSpec(byte[] spec, boolean checkConsistency, byte[] x, byte[] y, byte[] s);

    private final AmazonCorrettoCryptoProvider provider_;
    private final KeyFactory keyFactory;
    private ECParameterSpec spec = null;
    private byte[] encodedSpec = null;
    private ECInfo ecInfo = null;

    EcGen(AmazonCorrettoCryptoProvider provider) {
        provider_ = provider;
        try {
            keyFactory = KeyFactory.getInstance("EC");
        } catch (final NoSuchAlgorithmException ex) {
            throw new AssertionError(ex);
        }
    }

    @Override
    public KeyPair generateKeyPair() {
        if (spec == null) {
            try {
                initialize(DEFAULT_SPEC, null);
            } catch (final InvalidAlgorithmParameterException ex) {
                throw new RuntimeCryptoException(ex);
            }
        }
        // This will work for all curves up to unreasonably large sizes.
        // We do have bounds checking at the C++ level.
        final byte[] x = new byte[128];
        final byte[] y = new byte[128];
        final byte[] s = new byte[128];

        final boolean keyGenConsistency = provider_.hasExtraCheck(ExtraCheck.KEY_PAIR_GENERATION_CONSISTENCY);
        if (encodedSpec != null) {
            generateEcKeyFromSpec(encodedSpec, keyGenConsistency, x, y, s);
        } else {
            final NativeGroup group = ecInfo.getGroup();
            final NativeParams ecParams = getParams(ecInfo);
            group.useVoid(groupPtr ->
              ecParams.useVoid(ptr ->
                generateEcKey(ptr, groupPtr, keyGenConsistency, x, y, s)));
        }
        final ECPoint w = new ECPoint(new BigInteger(x), new BigInteger(y));
        final ECPrivateKeySpec privSpec = new ECPrivateKeySpec(new BigInteger(s), spec);
        final ECPublicKeySpec pubSpec = new ECPublicKeySpec(w, spec);
        try {
            return new KeyPair(keyFactory.generatePublic(pubSpec),
                    keyFactory.generatePrivate(privSpec));
        } catch (final InvalidKeySpecException ex) {
            throw new AssertionError(ex);
        }
    }

    @Override
    public void initialize(final AlgorithmParameterSpec params, final SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (params instanceof ECGenParameterSpec) {
            final ECGenParameterSpec tmpSpec = (ECGenParameterSpec) params;
            if (tmpSpec.getName() == null) {
                throw new NullPointerException("Curve name may not be null");
            }
            try {
                ecInfo = EcUtils.getSpecByName(tmpSpec.getName());
                spec = ecInfo.spec;
                encodedSpec = ecInfo.nid == 0 ? encodeSpec(spec) : null;
            } catch (final IllegalArgumentException ex) {
                throw new InvalidAlgorithmParameterException("Unknown curve name: "
                        + tmpSpec.getName(), ex);
            }
        } else if (params instanceof ECParameterSpec) {
            ecInfo = null;
            spec = (ECParameterSpec) params;
            encodedSpec = encodeSpec(spec);
        } else {
            throw new InvalidAlgorithmParameterException("Unsupported parameter spec: " + params);
        }
    }

    private static byte[] encodeSpec(final AlgorithmParameterSpec spec) {
        try {
            final AlgorithmParameters toEncode = AlgorithmParameters.getInstance("EC");
            toEncode.init(spec);
            return toEncode.getEncoded();
        } catch (final GeneralSecurityException | IOException ex) {
            throw new RuntimeCryptoException(ex);
        }
    }

    @Override
    public void initialize(final int keysize, final SecureRandom random)
            throws InvalidParameterException {
        try {
            final String curveName = "secp" + keysize + "r1";
            initialize(new ECGenParameterSpec(curveName), random);
        } catch (final InvalidAlgorithmParameterException ex) {
            throw new InvalidParameterException(ex.getMessage());
        }

    }

    private static NativeParams getParams(ECInfo info) {
        return PARAM_CACHE.computeIfAbsent(info, CACHE_LOADER).get();
    }

    private static final class NativeParams extends NativeResource {
        private NativeParams(long ptr) {
            super(ptr, EcGen::freeEcParams);
        }
    }
}
