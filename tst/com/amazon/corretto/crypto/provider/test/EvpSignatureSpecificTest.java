// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static com.amazon.corretto.crypto.provider.test.TestUtil.assumeMinimumVersion;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * These tests cover cases specific to certain algorithms rather than general to all EvpSignature algorithms.
 */
public class EvpSignatureSpecificTest {
    private static final AmazonCorrettoCryptoProvider NATIVE_PROVIDER = AmazonCorrettoCryptoProvider.INSTANCE;
    private static final BouncyCastleProvider BOUNCYCASTLE_PROVIDER = new BouncyCastleProvider();
    private static final byte[] MESSAGE = new byte[513];
    private final static KeyPair RSA_PAIR;
    private final static KeyPair DSA_PAIR;
    private final static KeyPair ECDSA_PAIR;

    static {
        for (int x = 0; x < MESSAGE.length; x++) {
            MESSAGE[x] = (byte) ((x % 256) - 128);
        }

        try {
            KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");
            kg.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));
            RSA_PAIR = kg.generateKeyPair();

            kg = KeyPairGenerator.getInstance("EC");
            kg.initialize(new ECGenParameterSpec("NIST P-384"));
            ECDSA_PAIR = kg.generateKeyPair();

            kg = KeyPairGenerator.getInstance("DSA");
            kg.initialize(2048);
            DSA_PAIR = kg.generateKeyPair();
        } catch (final GeneralSecurityException ex) {
            throw new RuntimeException(ex);
        }
    }

    private static void testKeyTypeMismatch(final String algorithm, final String baseType, final KeyPair badKeypair) throws GeneralSecurityException {
        final Signature signature = Signature.getInstance(algorithm, NATIVE_PROVIDER);

        assertThrows(InvalidKeyException.class, () -> signature.initSign(badKeypair.getPrivate()));
        assertThrows(InvalidKeyException.class, () -> signature.initVerify(badKeypair.getPublic()));


        // In this case, we are lying about what type of key it is, so it may not be caught until we
        // actually try to use it
        final RawKey fakekey = new RawKey(baseType, badKeypair.getPrivate());
        try {
            signature.initSign(fakekey);
            signature.update(MESSAGE);
            signature.sign();
            fail("Expected exception for fake key");
        } catch (final InvalidKeyException | SignatureException ex) {
            // Expected
        }
    }

    @Test
    public void signatureCorruptionSweeps() throws Exception {
        // Verify that, for any one-bit manipulation of the signature, we 1) get a bad signature result and 2) don't
        // throw an unexpected exception
        doCorruptionSweep("NONEwithDSA", DSA_PAIR);
        doCorruptionSweep("NONEwithECDSA", ECDSA_PAIR);
        doCorruptionSweep("SHA1withDSA", DSA_PAIR);
        doCorruptionSweep("SHA1withECDSA", ECDSA_PAIR);
        doCorruptionSweep("SHA1withRSA", RSA_PAIR);
    }

    private void doCorruptionSweep(final String algorithm, final KeyPair keyPair) throws Exception {
        byte[] message = new byte[] { 1, 2, 3, 4 };
        byte[] signature;

        Signature sig = Signature.getInstance(algorithm, NATIVE_PROVIDER);
        sig.initSign(keyPair.getPrivate());
        sig.update(message);
        signature = sig.sign();

        sig.initVerify(keyPair.getPublic());

        for (int bitpos = 0; bitpos < signature.length * 8; bitpos++) {
            byte[] badSignature = signature.clone();
            badSignature[bitpos / 8] ^= (1 << (bitpos % 8));

            sig.update(message);
            try {
                assertFalse(sig.verify(badSignature));
            } catch (SignatureException ex) {
                if (algorithm.contains("RSA")) {
                    // RSA is not allowed to fail with an exception
                    throw ex;
                }
            } catch (Throwable t) {
                throw new RuntimeException("Exception at bitpos " + bitpos, t);
            }
        }
    }

    @Test
    public void rsaWithDsaKey() throws GeneralSecurityException {
        testKeyTypeMismatch("SHA1withRSA", "RSA", DSA_PAIR);    }

    @Test
    public void ecdsaWithDsaKey() throws GeneralSecurityException {
        testKeyTypeMismatch("SHA1withECDSA", "EC", DSA_PAIR);
    }

    @Test
    public void dsaWithRsaKey() throws GeneralSecurityException {
        testKeyTypeMismatch("SHA1withDSA", "DSA", ECDSA_PAIR);    }

    @Test
    public void pssParametersForNonPssAlgorithm() throws GeneralSecurityException {
        Signature signature = Signature.getInstance("SHA1withRSA", NATIVE_PROVIDER);
        assertNull(signature.getParameters());

        try {
            signature.setParameter(PSSParameterSpec.DEFAULT);
            fail(signature.getAlgorithm());
        } catch (final InvalidAlgorithmParameterException ex) {
            // expected
        }

        signature = Signature.getInstance("SHA1withDSA", NATIVE_PROVIDER);
        try {
            signature.setParameter(PSSParameterSpec.DEFAULT);
            fail(signature.getAlgorithm());
        } catch (final InvalidAlgorithmParameterException ex) {
            // expected
        }

        signature = Signature.getInstance("SHA1withECDSA", NATIVE_PROVIDER);
        try {
            signature.setParameter(PSSParameterSpec.DEFAULT);
            fail(signature.getAlgorithm());
        } catch (final InvalidAlgorithmParameterException ex) {
            // expected
        }
    }

    @SuppressWarnings("deprecation")
    @Test
    public void deprecatedParameterLogic() throws GeneralSecurityException {
        final Signature signature = Signature.getInstance("SHA1withRSA", NATIVE_PROVIDER);
        assertThrows(UnsupportedOperationException.class, () -> {
            signature.getParameter("PSS");
        });
        assertThrows(UnsupportedOperationException.class, () -> {
            signature.setParameter("PSS", null);
        });
    }

    @Test(expected = SignatureException.class)
    public void uninitialized() throws GeneralSecurityException {
        final Signature signature = Signature.getInstance("SHA1withRSA", NATIVE_PROVIDER);
        signature.update(MESSAGE);
    }

    @Test
    public void wrongMode() throws GeneralSecurityException {
        final Signature signature = Signature.getInstance("SHA1withRSA", NATIVE_PROVIDER);
        signature.initSign(RSA_PAIR.getPrivate());
        signature.update(MESSAGE);
        try {
            signature.verify(new byte[128]);
            fail();
        } catch (final SignatureException ex) {
            // expected
        }

        signature.initVerify(RSA_PAIR.getPublic());
        signature.update(MESSAGE);
        try {
            signature.sign();
            fail();
        } catch (final SignatureException ex) {
            // expected
        }
    }

    @Test
    public void reinitImmediately() throws Exception {
        final Signature signature = Signature.getInstance("SHA1withRSA", NATIVE_PROVIDER);
        signature.initVerify(RSA_PAIR.getPublic());
        signature.initSign(RSA_PAIR.getPrivate());
        signature.update(MESSAGE);

        final Signature bcSig = Signature.getInstance("SHA1withRSA", BOUNCYCASTLE_PROVIDER);
        bcSig.initVerify(RSA_PAIR.getPublic());
        bcSig.update(MESSAGE);
        assertTrue(bcSig.verify(signature.sign()));
    }

    @Test
    public void reinitAfterData() throws Exception {
        final Signature signature = Signature.getInstance("SHA1withRSA", NATIVE_PROVIDER);
        signature.initVerify(RSA_PAIR.getPublic());
        signature.update(MESSAGE);
        signature.initSign(RSA_PAIR.getPrivate());
        signature.update(MESSAGE);

        final Signature bcSig = Signature.getInstance("SHA1withRSA", BOUNCYCASTLE_PROVIDER);
        bcSig.initVerify(RSA_PAIR.getPublic());
        bcSig.update(MESSAGE);
        assertTrue(bcSig.verify(signature.sign()));
    }

    @Test
    public void reinitAfterLotsOfData() throws Exception {
        final Signature signature = Signature.getInstance("SHA1withRSA", NATIVE_PROVIDER);
        signature.initVerify(RSA_PAIR.getPublic());
        for (int x = 0; x < 512; x++) {
            signature.update(MESSAGE);
        }
        signature.initSign(RSA_PAIR.getPrivate());
        signature.update(MESSAGE);

        final Signature bcSig = Signature.getInstance("SHA1withRSA", BOUNCYCASTLE_PROVIDER);
        bcSig.initVerify(RSA_PAIR.getPublic());
        bcSig.update(MESSAGE);
        assertTrue(bcSig.verify(signature.sign()));
    }

    @Test
    public void testBadArrayParams() throws Exception {
        final Signature signature = Signature.getInstance("SHA1withRSA", NATIVE_PROVIDER);
        signature.initVerify(RSA_PAIR.getPublic());

        assertThrows(IllegalArgumentException.class, () -> signature.update(MESSAGE, -1, 1));
        assertThrows(IllegalArgumentException.class, () -> signature.update(MESSAGE, 0, MESSAGE.length + 1));
        assertThrows(IllegalArgumentException.class, () -> signature.update(MESSAGE, 10, MESSAGE.length - 1));
        assertThrows(IllegalArgumentException.class, () -> signature.update(MESSAGE, 0, -5));
        assertThrows(IllegalArgumentException.class, () -> signature.update(MESSAGE, 2, Integer.MAX_VALUE));

        final byte[] fakeSignature = new byte[2048];
        assertThrows(IllegalArgumentException.class, () -> signature.verify(fakeSignature, -1, 1));
        assertThrows(IllegalArgumentException.class, () -> signature.verify(fakeSignature, 0, fakeSignature.length + 1));
        assertThrows(IllegalArgumentException.class, () -> signature.verify(fakeSignature, 10, fakeSignature.length - 1));
        assertThrows(IllegalArgumentException.class, () -> signature.verify(fakeSignature, 0, -5));
        assertThrows(IllegalArgumentException.class, () -> signature.verify(fakeSignature, 2, Integer.MAX_VALUE));
    }

    @Test
    public void testRsaWithoutCrtParams() throws Exception {
        final RSAPrivateKey prvKey = (RSAPrivateKey) RSA_PAIR.getPrivate();
        final KeyFactory kf = KeyFactory.getInstance("RSA");
        final PrivateKey strippedKey = kf.generatePrivate(new RSAPrivateKeySpec(prvKey.getModulus(), prvKey.getPrivateExponent()));
        final Signature signature = Signature.getInstance("SHA1withRSA", NATIVE_PROVIDER);
        signature.initSign(strippedKey);
        signature.update(MESSAGE);
        final byte[] validSignature = signature.sign();
        signature.initVerify(RSA_PAIR.getPublic());
        signature.update(MESSAGE);
        assertTrue(signature.verify(validSignature));
    }

    /**
     * We used to leave undrained openssl errors after parsing ECDSA keys. This could be seen if you immediately
     * had a failed AES-GCM decryption following the ECDSA parse where you'd get the incorrect exception back.
     */
    @Test
    public void ecdsaSignCorruptsErrorState() throws Exception {
        assumeMinimumVersion("1.0.1", AmazonCorrettoCryptoProvider.INSTANCE);
        final KeyPairGenerator kg = KeyPairGenerator.getInstance("EC", AmazonCorrettoCryptoProvider.INSTANCE);
        kg.initialize(384);
        final KeyPair pair = kg.generateKeyPair();
        final Signature signer = Signature.getInstance("SHA256withECDSA", AmazonCorrettoCryptoProvider.INSTANCE);
        signer.initSign(pair.getPrivate());
        signer.sign(); // Ignore result

        Cipher c = Cipher.getInstance("AES/GCM/NoPadding", AmazonCorrettoCryptoProvider.INSTANCE);
        c.init(Cipher.DECRYPT_MODE,
                new SecretKeySpec("Yellow Submarine".getBytes(StandardCharsets.UTF_8), "AES"),
                new GCMParameterSpec(128, new byte[12]));
        try {
            c.doFinal(new byte[32]);
        } catch (final AEADBadTagException ex) {
            // expected
        }
    }

    /**
     * This test iterates over every implemented algorithm and ensures that it is compatible with the
     * equivalent BouncyCastle implementation. It doesn't check negative cases as the more detailed tests
     * cover that for algorithm families.
     */
    @Test
    public void simpleCorrectnessAllAlgorithms() throws Throwable {
        final Pattern namePattern = Pattern.compile("(SHA(\\d+)|NONE)with([A-Z]+)(inP1363Format)?");
        final Set<Provider.Service> services = AmazonCorrettoCryptoProvider.INSTANCE.getServices();
        final byte[] message = {1, 2, 3, 4, 5, 6, 7, 8};
        for (Provider.Service service : services) {
            if (!service.getType().equals("Signature")) {
                continue;
            }
            final String algorithm = service.getAlgorithm();
            String bcAlgorithm = algorithm;
            AlgorithmParameterSpec keyGenSpec = null;
            String keyGenAlgorithm = null;
            final Matcher m = namePattern.matcher(algorithm);

            if (!m.matches()) {
                Assert.fail("Unexpected algorithm name: " + algorithm);
            }

            final String shaLength = m.group(2);
            final String base = m.group(3);
            final String ieeeFormat = m.group(4);

            int ffSize = 0; // Finite field size used with RSA and DSA
            switch (m.group(1)) {
                case "SHA1":
                case "SHA224":
                case "SHA256":
                    ffSize = 2048;
                    break;
                case "SHA384":
                    ffSize = 3072;
                    break;
                case "SHA512":
                case "NONE":
                    ffSize = 4096;
                    break;
                default:
                    Assert.fail("Unexpected algorithm name: " + algorithm);
            }
            if ("ECDSA".equals(base)) {
                keyGenAlgorithm = "EC";
                if (null == shaLength || "1".equals(shaLength) || "512".equals(shaLength)) {
                    keyGenSpec = new ECGenParameterSpec("NIST P-521");
                } else {
                    keyGenSpec = new ECGenParameterSpec("NIST P-" + shaLength);
                }

                if (ieeeFormat != null) {
                    bcAlgorithm = bcAlgorithm.replace("withECDSAinP1363Format", "withPLAIN-ECDSA");
                }
            } else {
                keyGenAlgorithm = base;
                if (base.equals("DSA")) {
                    ffSize = Math.min(ffSize, 3072);
                }
            }

            final KeyPairGenerator kg = KeyPairGenerator.getInstance(keyGenAlgorithm);
            if (keyGenSpec != null) {
                kg.initialize(keyGenSpec);
            } else {
                kg.initialize(ffSize);
            }
            final KeyPair pair = kg.generateKeyPair();

            final Signature nativeSig = Signature.getInstance(algorithm, AmazonCorrettoCryptoProvider.INSTANCE);
            final Signature bcSig = Signature.getInstance(bcAlgorithm, TestUtil.BC_PROVIDER);

            try {
                // Generate with native and verify with BC
                nativeSig.initSign(pair.getPrivate());
                bcSig.initVerify(pair.getPublic());
                nativeSig.update(message);
                bcSig.update(message);
                byte[] signature = nativeSig.sign();
                assertTrue("Native->BC: " + algorithm, bcSig.verify(signature));

                // Generate with BC and verify with native
                nativeSig.initVerify(pair.getPublic());
                bcSig.initSign(pair.getPrivate());
                nativeSig.update(message);
                bcSig.update(message);
                signature = bcSig.sign();
                assertTrue("BC->Native: " + algorithm, nativeSig.verify(signature));
            } catch (SignatureException ex) {
                throw new AssertionError(algorithm, ex);
            }
        }
    }

    @SuppressWarnings("serial")
    private static class RawKey implements PublicKey, PrivateKey {
        private final String algorithm_;
        private final byte[] encoded_;
        private final String format_;

        public RawKey(final String algorithm, final Key key) {
            this(algorithm, key.getEncoded(), key.getFormat());
        }

        public RawKey(final String algorithm, final byte[] encoded, final String format) {
            algorithm_ = algorithm;
            encoded_ = encoded.clone();
            format_ = format;
        }

        @Override
        public String getAlgorithm() {
            return algorithm_;
        }

        @Override
        public byte[] getEncoded() {
            return encoded_.clone();
        }

        @Override
        public String getFormat() {
            return format_;
        }
    }
}
