// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test.integration;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class HTTPSTestParameters {
    static final String PROTOCOL_TLS_1_2 = "TLSv1.2";
    static final String PROTOCOL_TLS_1_3 = "TLSv1.3";

    // Map of key algorithm ("RSA", "ECDSA", "DSA") to supported key sizes
    private static final Map<String, List<Integer>> ALGO_TO_KEY_BITS;

    public static final List<String> SIGNATURE_METHODS_TO_TEST = Arrays.asList(
            "SHA256withDSA",

            // Not supported in the built-in JCE provider. Uncomment (and rerun the TestCertificateGenerator) when we
            // add support for these methods.
            //"SHA384withDSA",
            //"SHA512withDSA",

            // SHA1with* is rejected outright by BouncyCastle and/or SunJCE, which is reasonable enough at this point.
            // We'll just not test any of the sha1 cert path cases as they'll all be validated and rejected soon enough.
            //"SHA1withDSA",
            //"SHA1withECDSA",
            //"SHA1withRSA",
            //"SHA1withDSA",

            "SHA256withRSA",
            "SHA384withRSA",
            "SHA512withRSA",
            "SHA256withECDSA",
            "SHA384withECDSA",
            "SHA512withECDSA"

    );
    static char[] SUPER_SECURE_PASSWORD = "hunter2".toCharArray();

    static {
        Map<String,List<Integer>> algoKeyBitsMap = new HashMap<>();

        algoKeyBitsMap.put("RSA", Arrays.asList(1024, 2048, 3072, 7680, 15360));
        algoKeyBitsMap.put("ECDSA", Arrays.asList(256, 384, 521));
        algoKeyBitsMap.put("DSA", Arrays.asList(1024, 2048, 3072));

        ALGO_TO_KEY_BITS = Collections.unmodifiableMap(algoKeyBitsMap);
    }

    public static List<Integer> keySizesForSignatureMethod(String signatureMethod) {
        String keyType = getKeyType(signatureMethod);

        ArrayList<Integer> sizes = new ArrayList<>(ALGO_TO_KEY_BITS.get(keyType));

        if (signatureMethod.equals("SHA1withDSA")) {
            // Java does not allow a keys over 1024 bits to be used with this method
            sizes.removeIf(size -> size > 1024);
        }

        return sizes;
    }

    static String getKeyType(String signatureMethod) {
        return signatureMethod.replaceAll(".*with", "");
    }

    static String protocolFromSuite(final String cipherSuite) {
        // We only test on 1.3 and 1.2 for now.
        // Everything older is being deprecated and none of our crypto
        // should do anything different for older versions anyway.
        switch (cipherSuite) {
            case "TLS_AES_128_GCM_SHA256":
            case "TLS_AES_256_GCM_SHA384":
            case "TLS_CHACHA20_POLY1305_SHA256":
            case "TLS_AES_128_CCM_SHA256":
            case "TLS_AES_128_CCM_8_SHA256":
                return PROTOCOL_TLS_1_3;
            default:
                return PROTOCOL_TLS_1_2;
        }
    }

    /**
     * Returns {@code true} iff the TLS ciphersuite {@code suite} can be used with
     * certificates signed using
     * {@code signature}.
     *
     * @param suite     the TLS ciphersuite
     * @param signatureMethod the algorithm used to sign the TLS certificate
     * @returns true if certificates signed by {@code signature} can be used with
     *          {@code suite}}
     * @see https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html
     */
    static boolean suiteMatchesSignature(final String suite, final String signatureMethod) {
        final String keyType = getKeyType(signatureMethod);

        // TLS 1.3 only supports RSA and ECDSA certificates
        if (protocolFromSuite(suite).equals(PROTOCOL_TLS_1_3)
                && (keyType.equals("RSA") || keyType.equals("ECDSA"))) {
            return true;
        }

        // DSA is called DSS in ciphersuites
        if (keyType.equals("DSA")) {
            return suite.contains("DSS");
        }

        // Otherwise, everything matches up
        return suite.contains(keyType);
    }
}
