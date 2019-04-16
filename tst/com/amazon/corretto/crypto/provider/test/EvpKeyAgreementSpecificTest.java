// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyInvokeExplicit;

import java.util.Arrays;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.KeyAgreement;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import org.junit.Test;

/**
 * This class contains non-parameterized tests to cover
 * specific cases.
 **/
public class EvpKeyAgreementSpecificTest {
    private static final Class<?> SPI_CLASS;
    private static final int EC_TYPE = 408;
    private static final int DH_TYPE = 28;
    private final KeyPair EC_KEYPAIR;
    private final KeyPair DH_KEYPAIR;

    static {
      try {
          SPI_CLASS = Class.forName("com.amazon.corretto.crypto.provider.EvpKeyAgreement");
      } catch (final ClassNotFoundException ex) {
          throw new AssertionError(ex);
      }
    }

    public EvpKeyAgreementSpecificTest() throws GeneralSecurityException {
        // Force loading of native library
        KeyAgreement.getInstance("ECDH", AmazonCorrettoCryptoProvider.INSTANCE);

        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("NIST P-224"));
        EC_KEYPAIR = gen.generateKeyPair();
        gen = KeyPairGenerator.getInstance("DH");
        gen.initialize(1024);
        DH_KEYPAIR = gen.generateKeyPair();
    }

    @Test
    public void wrongKeyTypes() throws Throwable {
        assertThrows(InvalidKeyException.class, () -> agree(
            EC_KEYPAIR.getPrivate().getEncoded(),
            DH_KEYPAIR.getPublic().getEncoded(),
            EC_TYPE));

        assertThrows(InvalidKeyException.class, () -> agree(
            DH_KEYPAIR.getPrivate().getEncoded(),
            EC_KEYPAIR.getPublic().getEncoded(),
            EC_TYPE));

    }

    @Test
    public void paramMismatch() throws Throwable {
        assertThrows(InvalidKeyException.class, () -> agree(
            EC_KEYPAIR.getPrivate().getEncoded(),
            EvpKeyAgreementTest.buildKeyOnWrongCurve((ECPublicKey) EC_KEYPAIR.getPublic()).getEncoded(),
            EC_TYPE));

        assertThrows(InvalidKeyException.class, () -> agree(
            DH_KEYPAIR.getPrivate().getEncoded(),
            EvpKeyAgreementTest.buildDhKeyWithRandomParams(1024).getEncoded(),
            DH_TYPE));

    }

    @Test
    public void invalidDerEncodings() throws Throwable {
        byte[] privKey = EC_KEYPAIR.getPrivate().getEncoded();
        byte[] pubKey = EC_KEYPAIR.getPublic().getEncoded();

        assertThrows(InvalidKeyException.class, () -> agree(
            new byte[0],
            pubKey,
            EC_TYPE));

        assertThrows(InvalidKeyException.class, () -> agree(
            privKey,
            new byte[0],
            EC_TYPE));


        assertThrows(InvalidKeyException.class, () -> agree(
            Arrays.copyOf(privKey, privKey.length + 1),
            EC_KEYPAIR.getPublic().getEncoded(),
            EC_TYPE));

        assertThrows(InvalidKeyException.class, () -> agree(
            privKey,
            Arrays.copyOf(pubKey, pubKey.length + 1),
            EC_TYPE));
    }

    @Test
    public void evilEcKeys() throws Throwable {
        byte[] privKey = EC_KEYPAIR.getPrivate().getEncoded();
        assertThrows(InvalidKeyException.class, () -> agree(
            privKey,
            EvpKeyAgreementTest.buildKeyAtInfinity(
                (ECPublicKey) EC_KEYPAIR.getPublic()).getEncoded(),
            EC_TYPE));

        assertThrows(InvalidKeyException.class, () -> agree(
            privKey,
            EvpKeyAgreementTest.buildKeyOffCurve(
               (ECPublicKey) EC_KEYPAIR.getPublic()).getEncoded(),
            EC_TYPE));

    }

    private static byte[] agree(byte[] privateKeyDer, byte[] publicKeyDer, int keyType)
      throws Throwable {
        return sneakyInvokeExplicit(SPI_CLASS, "agree", null,
            privateKeyDer, publicKeyDer, keyType, false);
    }
}
