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
}
