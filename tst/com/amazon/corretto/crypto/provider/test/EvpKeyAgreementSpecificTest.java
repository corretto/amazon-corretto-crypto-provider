// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyInvokeExplicit;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.util.Arrays;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
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
    private static final KeyPair EC_KEYPAIR;
    private static final KeyPair DH_KEYPAIR;

    static {
      try {
          SPI_CLASS = Class.forName("com.amazon.corretto.crypto.provider.EvpKeyAgreement");

          // Force loading of native library
          KeyAgreement.getInstance("ECDH", AmazonCorrettoCryptoProvider.INSTANCE);

          KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
          gen.initialize(new ECGenParameterSpec("NIST P-224"));
          EC_KEYPAIR = gen.generateKeyPair();
          gen = KeyPairGenerator.getInstance("DH");
          gen.initialize(1024);
          DH_KEYPAIR = gen.generateKeyPair();
      } catch (final Exception ex) {
          throw new AssertionError(ex);
      }
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

    // This test covers three-way DH
    @Test
    public void dh3() throws Throwable {
        final KeyPairGenerator kg = KeyPairGenerator.getInstance("DH");
        kg.initialize(1024);
        final KeyPair alice = kg.generateKeyPair();
        final KeyPair bob = kg.generateKeyPair();
        final KeyPair carol = kg.generateKeyPair();

        final KeyAgreement aNativeKA = KeyAgreement.getInstance("DH", AmazonCorrettoCryptoProvider.INSTANCE);
        final KeyAgreement bNativeKA = KeyAgreement.getInstance("DH", AmazonCorrettoCryptoProvider.INSTANCE);
        final KeyAgreement cNativeKA = KeyAgreement.getInstance("DH", AmazonCorrettoCryptoProvider.INSTANCE);

        final KeyAgreement aSunKA = KeyAgreement.getInstance("DH", "SunJCE");
        final KeyAgreement bSunKA = KeyAgreement.getInstance("DH", "SunJCE");
        final KeyAgreement cSunKA = KeyAgreement.getInstance("DH", "SunJCE");

        aNativeKA.init(alice.getPrivate());
        aSunKA.init(alice.getPrivate());

        bNativeKA.init(bob.getPrivate());
        bSunKA.init(bob.getPrivate());

        cNativeKA.init(carol.getPrivate());
        cSunKA.init(carol.getPrivate());

        // Phase 1
        final Key acNative = aNativeKA.doPhase(carol.getPublic(), false);
        final Key acSun = aSunKA.doPhase(carol.getPublic(), false);
        assertKeyEquals("AC keys", acSun, acNative);

        final Key baNative = bNativeKA.doPhase(alice.getPublic(), false);
        final Key baSun = bSunKA.doPhase(alice.getPublic(), false);
        assertKeyEquals("BA keys", baSun, baNative);

        final Key cbNative = cNativeKA.doPhase(bob.getPublic(), false);
        final Key cbSun = cSunKA.doPhase(bob.getPublic(), false);
        assertKeyEquals("CB keys", cbSun, cbNative);

        // Complete agreement
        assertNull(aNativeKA.doPhase(cbNative, true));
        assertNull(aSunKA.doPhase(cbSun, true));

        assertNull(bNativeKA.doPhase(acNative, true));
        assertNull(bSunKA.doPhase(acSun, true));

        assertNull(cNativeKA.doPhase(baNative, true));
        assertNull(cSunKA.doPhase(baSun, true));

        // Get the results and ensure they match the default Java implementation
        final byte[] aliceNativeSecret = aNativeKA.generateSecret();
        final byte[] aliceSunSecret = aSunKA.generateSecret();
        assertArrayEquals("Alice secrets", aliceSunSecret, aliceNativeSecret);

        final byte[] bobNativeSecret = bNativeKA.generateSecret();
        final byte[] bobSunSecret = bSunKA.generateSecret();
        assertArrayEquals("Bob secrets", bobSunSecret, bobNativeSecret);

        final byte[] carolNativeSecret = cNativeKA.generateSecret();
        final byte[] carolSunSecret = cSunKA.generateSecret();
        assertArrayEquals("Carol secrets", carolSunSecret, carolNativeSecret);

        // Finally ensure that the values all match
        assertArrayEquals("Alice and Bob", aliceNativeSecret, bobNativeSecret);
        assertArrayEquals("Alice and Carol", aliceNativeSecret, carolNativeSecret);
    }

    private static void assertKeyEquals(String message, Key a, Key b) {
        assertEquals(message, a.getFormat(), b.getFormat());
        assertArrayEquals(message, a.getEncoded(), b.getEncoded());
    }

    private static byte[] agree(byte[] privateKeyDer, byte[] publicKeyDer, int keyType)
      throws Throwable {
        return sneakyInvokeExplicit(SPI_CLASS, "agree", null,
            privateKeyDer, publicKeyDer, keyType, false);
    }
}
