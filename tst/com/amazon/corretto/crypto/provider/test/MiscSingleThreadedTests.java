// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import static org.junit.Assert.assertTrue;
import static com.amazon.corretto.crypto.provider.test.TestUtil.assumeMinimumVersion;
import static com.amazon.corretto.crypto.provider.test.TestUtil.saveProviders;
import static com.amazon.corretto.crypto.provider.test.TestUtil.restoreProviders;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Signature;

/**
 * Contains miscellaneous tests which must be run in a single-threaded environment.
 */
public class MiscSingleThreadedTests {


    /**
     * We do not (currently) support the signature NONEwithRSA, but the JCE implements it internally with
     * Cipher.getInstance("RSA/ECB/PKCS1Padding"), which we do support. In certain cases we can cause this to fail.
     * It does require that the provider ordering be relatively specific and that we call .getProvider() on
     * the Signature objects prior to initializing them.
     */
    @Test
    public void testNoneWithRsa() throws Exception {
        assumeMinimumVersion("1.0.1", AmazonCorrettoCryptoProvider.INSTANCE);

        final Provider[] oldProviders = saveProviders();
        try {
            AmazonCorrettoCryptoProvider.install();
            final KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");
            kg.initialize(2048);
            final KeyPair pair = kg.generateKeyPair();

            final Signature signer = Signature.getInstance("NONEwithRSA");
            signer.getProvider();
            signer.initSign(pair.getPrivate());
            signer.update("TestData".getBytes(StandardCharsets.UTF_8));
            final byte[] signature = signer.sign();

            final Signature verifier = Signature.getInstance("NONEwithRSA");
            verifier.getProvider();
            verifier.initVerify(pair.getPublic());
            verifier.update("TestData".getBytes(StandardCharsets.UTF_8));
            assertTrue(verifier.verify(signature));
        } finally {
            restoreProviders(oldProviders);
        }
    }
}
