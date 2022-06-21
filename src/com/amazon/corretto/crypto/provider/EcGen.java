// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

import com.amazon.corretto.crypto.provider.EcUtils.ECInfo;

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
     * Generates a new EC key and returns a pointer to it.
     *
     * @param params
     *            a native pointer created by {@link #buildEcParams(int)}
     * @param curve
     *            a native pointer returned by {@link ECInfo#groupPtr()}
     * @param checkConsistency
     *            Run additional consistency checks on the generated keypair
     */
    private static native long generateEvpEcKey(long params, boolean checkConsistency);

    /**
     * Generates a new EC key and returns a pointer to it.
     *
     * @param spec
     *            an ASN.1 encoded {@link ECParameterSpec}
     * @param checkConsistency
     *            Run additional consistency checks on the generated keypair
     */
    private static native long generateEvpEcKeyFromSpec(byte[] spec, boolean checkConsistency);

    private final AmazonCorrettoCryptoProvider provider_;
    private ECParameterSpec spec = null;
    private byte[] encodedSpec = null;
    private ECInfo ecInfo = null;

    EcGen(AmazonCorrettoCryptoProvider provider) {
        Loader.checkNativeLibraryAvailability();
        provider_ = provider;
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

        final EvpEcPrivateKey privateKey;
        final boolean keyGenConsistency = provider_.hasExtraCheck(ExtraCheck.KEY_PAIR_GENERATION_CONSISTENCY);
        if (encodedSpec != null) {
            privateKey = new EvpEcPrivateKey(generateEvpEcKeyFromSpec(encodedSpec, keyGenConsistency));
        } else {
            final NativeParams ecParams = getParams(ecInfo);
            privateKey = new EvpEcPrivateKey((long)
                ecParams.use(ptr ->
                    generateEvpEcKey(ptr, keyGenConsistency)));
        }
        final EvpEcPublicKey publicKey = privateKey.getPublicKey();

        return new KeyPair(publicKey, privateKey);
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
            // Explicitly list default curves
            // Mapping from OpenJDK
           final String curveName;
           switch (keysize) {
               case 224:
                   curveName = "secp224r1"; // NIST P-224
                   break;
               case 256:
                   curveName = "secp256r1"; // NIST P-256
                   break;
               case 384:
                   curveName = "secp384r1"; // NIST P-384
                   break;
               case 521:
                   curveName = "secp521r1"; // NIST P-521
                   break;
               default:
                   throw new InvalidParameterException("No default NIST prime curve for keysize " + keysize);
           }
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
