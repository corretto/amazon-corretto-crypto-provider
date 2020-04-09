// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeFalse;
import static org.junit.Assume.assumeTrue;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.DSAKey;
import java.security.interfaces.ECKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.*;
import java.util.function.BiFunction;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;

@RunWith(Parameterized.class)
public class EvpSignatureTest {
    private static final Provider NATIVE_PROVIDER = AmazonCorrettoCryptoProvider.INSTANCE;
    private static final int[] LENGTHS = new int[] { 1, 3, 4, 7, 8, 16, 32, 48, 64, 128, 256, 1024, 1536, 2049 };
    private static final List<String> BASES = Arrays.asList("DSA", "RSA", "ECDSA");
    private static final List<String> HASHES = Arrays.asList("NONE", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512");
    private static final int[] MESSAGE_LENGTHS = new int[] { 0, 1, 16, 32, 2047, 2048, 2049, 4100 };
    private static Map<String, KeyPair> KEY_PAIRS;

    static {
        try {
            final Map<String, KeyPair> tmpMap = new HashMap<>();
            KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");
            kg.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));
            tmpMap.put("RSA", kg.generateKeyPair());

            kg = KeyPairGenerator.getInstance("EC");
            kg.initialize(new ECGenParameterSpec("NIST P-521"));
            tmpMap.put("ECDSA", kg.generateKeyPair());

            kg = KeyPairGenerator.getInstance("DSA");
            kg.initialize(2048);
            tmpMap.put("DSA", kg.generateKeyPair());

            KEY_PAIRS = Collections.unmodifiableMap(tmpMap);
        } catch (final GeneralSecurityException ex) {
            throw new RuntimeException(ex);
        }
    }

    @Parameters(name = "{1} message_ length {2}. Read-only: {3}, Sliced: {4}")
    public static Collection<Object[]> data() {
        final List<Object[]> result = new ArrayList<>();
        for (final String base : BASES) {
            next_hash: for (final String hash : HASHES) {
                int[] lengths = MESSAGE_LENGTHS;
                if (hash.equals("NONE")) {
                    switch (base) {
                        case "RSA":
                            // RSA with NONE is not supported, as RSA padding requires that the hash be known
                            continue next_hash;
                        case "DSA":
                            // DSA raw messages are truncated when they exceed the bit length of Q (XX bits) so there's no
                            // point in testing much larger
                            lengths = new int[] { 0, 1, 16, 24, 25, 26, 27, 28, 29 };
                            break;
                        case "ECDSA":
                            // Similarly, ECDSA raw messages are truncated at the modulus size (384 bits in our case -
                            // so 48 bytes).
                            lengths = new int[] { 0, 1, 16, 32, 33, 47, 48, 49, 50 };
                            break;
                    }

                }

                for (final int length : lengths) {
                    String algorithm = String.format("%swith%s", hash, base);
                    result.add(new Object[] { base, algorithm, length, false, false });
                    result.add(new Object[] { base, algorithm, length, true, false });
                    result.add(new Object[] { base, algorithm, length, false, true });
                    result.add(new Object[] { base, algorithm, length, true, true });
                    if (base.equals("ECDSA") && !hash.equals("NONE")) {
                        algorithm = algorithm + "inP1363Format";
                        result.add(new Object[] { base, algorithm, length, false, false });
                        result.add(new Object[] { base, algorithm, length, true, false });
                        result.add(new Object[] { base, algorithm, length, false, true });
                        result.add(new Object[] { base, algorithm, length, true, true });
                    }
                }
            }
        }
        return result;
    }

    private final String base_;
    private final String algorithm_;
    private final boolean readOnly_;
    private final boolean slice_;
    private final KeyPair keyPair_;
    private final int length_;

    private byte[] message_;
    private Signature signer_;
    private Signature verifier_;
    private Signature jceVerifier_;
    private byte[] goodSignature_;

    public EvpSignatureTest(final String base, final String algorithm, final int length, boolean readOnly, boolean slice) throws GeneralSecurityException {
        base_ = base;
        readOnly_ = readOnly;
        slice_ = slice;
        length_ = length;

        if (base_.startsWith("RSA")) {
            keyPair_ = KEY_PAIRS.get("RSA");
        } else {
            keyPair_ = KEY_PAIRS.get(base_);
        }
        algorithm_ = algorithm;
    }

    @Before
    public void setup() throws GeneralSecurityException {
        signer_ = getNativeSigner();
        signer_.initSign(keyPair_.getPrivate());
        verifier_ = getNativeSigner();
        verifier_.initVerify(keyPair_.getPublic());
        jceVerifier_ = getJceSigner();
        jceVerifier_.initVerify(keyPair_.getPublic());

        message_ = new byte[length_];

        for (int x = 0; x < message_.length; x++) {
            message_[x] = (byte) ((x % 256) - 128);
        }

        final Signature jceSigner = getJceSigner();
        jceSigner.initSign(keyPair_.getPrivate());
        jceSigner.update(message_);
        goodSignature_ = jceSigner.sign();
    }

    @After
    public void teardown() {
        // It is unclear if JUnit always properly releases references to classes and thus we may have memory leaks
        // if we do not properly null our references
        signer_ = null;
        verifier_ = null;
        jceVerifier_ = null;
        message_ = null;
        goodSignature_ = null;
    }

    private Signature getNativeSigner() throws NoSuchAlgorithmException {
        return Signature.getInstance(algorithm_, NATIVE_PROVIDER);
    }

    private Signature getJceSigner() throws NoSuchAlgorithmException {
        // BouncyCastle uses a different naming scheme for P1363 schemes
        String bcName = algorithm_.replace("withECDSAinP1363Format", "withPLAIN-ECDSA");
        return Signature.getInstance(bcName, TestUtil.BC_PROVIDER);
    }

    private void assumeNonByteBufferTestApplicable() {
        assumeFalse("Read-only and slice tests are not applicable to non-ByteBuffers.", readOnly_ || slice_);
    }

    @Test
    public void signSinglePass() throws GeneralSecurityException {
        assumeNonByteBufferTestApplicable();
        signer_.update(message_);
        jceVerifier_.update(message_);
        assertTrue(jceVerifier_.verify(signer_.sign()));
    }

    @Test
    public void signSingleByte() throws GeneralSecurityException {
        assumeNonByteBufferTestApplicable();
        for (final byte b : message_) {
            signer_.update(b);
        }
        jceVerifier_.update(message_);
        assertTrue(jceVerifier_.verify(signer_.sign()));
    }

    @Test
    public void signSubArray() throws GeneralSecurityException {
        assumeNonByteBufferTestApplicable();
        for (final int length : LENGTHS) {
            if (length > message_.length) {
                break;
            }
            for (int x = 0; x < message_.length; x += length) {
                final int len = x + length > message_.length ? message_.length - x : length;
                signer_.update(message_, x, len);
            }
            jceVerifier_.update(message_);
            assertTrue(Integer.toString(length), jceVerifier_.verify(signer_.sign()));
        }
    }

    @Test
    public void signSingleByteBufferWrap() throws GeneralSecurityException {
        testSingleByteBuffer(true, applyParameters((ByteBuffer.wrap(message_))));
    }

    @Test
    public void signSubByteBufferWrap() throws GeneralSecurityException {
        testSubByteBuffer(true, (position, length) -> applyParameters(ByteBuffer.wrap(message_, position, length)));
    }

    @Test
    public void signSingleByteBuffer() throws GeneralSecurityException {
        final ByteBuffer bbuff = ByteBuffer.allocate(message_.length);
        bbuff.put(message_);
        bbuff.flip();
        testSingleByteBuffer(true, applyParameters(bbuff));
    }

    @Test
    public void signSubByteBuffer() throws GeneralSecurityException {
        final ByteBuffer bbuff = ByteBuffer.allocate(message_.length);
        testSubByteBuffer(true, new BufferSplitter(bbuff));
    }

    @Test
    public void signSingleByteBufferDirect() throws GeneralSecurityException {
        final ByteBuffer bbuff = ByteBuffer.allocateDirect(message_.length);
        bbuff.put(message_);
        bbuff.flip();
        testSingleByteBuffer(true, applyParameters(bbuff));
    }

    @Test
    public void signSubByteBufferDirect() throws GeneralSecurityException {
        final ByteBuffer bbuff = ByteBuffer.allocateDirect(message_.length);
        testSubByteBuffer(true, new BufferSplitter(bbuff));
    }

    @Test
    public void verifySinglePass() throws GeneralSecurityException {
        assumeNonByteBufferTestApplicable();
        verifier_.update(message_);

        assertTrue(verifier_.verify(goodSignature_));
    }

    @Test
    public void verifyBadSignature() throws GeneralSecurityException {
        assumeNonByteBufferTestApplicable();
        verifier_.update(message_);
        byte[] badSignature = goodSignature_.clone();
        badSignature[badSignature.length - 1]++;
        try {
            assertFalse(verifier_.verify(badSignature));
        } catch (final SignatureException ex) {
            if (algorithm_.contains("RSA")) {
                // RSA is not allowed to fail with an exception
                throw ex;
            }
        }
    }

    @Test
    public void verifyTruncatedSignature() throws GeneralSecurityException {
        assumeNonByteBufferTestApplicable();
        verifier_.update(message_);
        byte[] badSignature = Arrays.copyOf(goodSignature_, goodSignature_.length - 1);
        // Truncated signatures will sometime return false and sometimes throw an exception. Both are acceptable
        try {
            assertFalse(verifier_.verify(badSignature));
        } catch (final SignatureException ex) {
            if (algorithm_.contains("RSA")) {
                // RSA is not allowed to fail with an exception
                throw ex;
            }
        }
    }

    @Test
    public void verifyWrongMessage() throws GeneralSecurityException {
        // Modification of body of the message only works
        // if the message is not empty
        assumeTrue(message_.length > 0);

        byte[] msgCopy = message_.clone();
        msgCopy[0]++;
        verifier_.update(msgCopy);
        assertFalse(verifier_.verify(goodSignature_));
    }

    @Test
    public void verifyTruncatedMessage() throws Exception {
        // If we're already beyond the message size limit, we expect truncation to be ignored
        assumeTrue(message_.length <= getMessageSizeLimit());
        assumeTrue(message_.length > 0);

        verifier_.update(Arrays.copyOf(message_, message_.length - 1));
        assertFalse(verifier_.verify(goodSignature_));
    }

    @Test
    public void verifyExtendedMessage() throws Exception {
        // If we're just at the message size limit, any additional bytes will be ignored
        assumeTrue((message_.length + 1) <= getMessageSizeLimit());

        assumeNonByteBufferTestApplicable();
        verifier_.update(message_);
        verifier_.update((byte) 0x44);
        assertFalse(verifier_.verify(goodSignature_));

    }

    private int getMessageSizeLimit() {
        // For DSA and ECDSA raw algorithms, there is a limit to which the "digest" is truncated. We need to make sure
        // we're not past that limit.

        // Note that ignoring the extension is per the spec - see FIPS.186-4 for both DSA and ECDSA specifying that the
        // leftmost min(N, outlen) bits of Hash(M) be used, for values of N depending on the domain parameters
        switch (algorithm_) {
            case "NONEwithDSA": {
                DSAKey dsaKey = (DSAKey) keyPair_.getPublic();

                return dsaKey.getParams().getQ().bitLength() / 8;
            }
            case "NONEwithECDSA": {
                ECKey ecKey = (ECKey) keyPair_.getPublic();

                return ecKey.getParams().getOrder().bitLength() / 8;
            }
            default:
                return Integer.MAX_VALUE;
        }
    }

    @Test
    public void verifySingleByte() throws GeneralSecurityException {
        assumeNonByteBufferTestApplicable();
        for (final byte b : message_) {
            verifier_.update(b);
        }

        assertTrue(verifier_.verify(goodSignature_));
    }

    @Test
    public void verifySubArray() throws GeneralSecurityException {
        assumeNonByteBufferTestApplicable();
        for (final int length : LENGTHS) {
            if (length > message_.length) {
                break;
            }
            for (int x = 0; x < message_.length; x += length) {
                final int len = x + length > message_.length ? message_.length - x : length;
                verifier_.update(message_, x, len);
            }

            assertTrue(Integer.toString(length), verifier_.verify(goodSignature_));
        }
    }

    @Test
    public void verifySignatureInLargerArray() throws SignatureException {
        assumeNonByteBufferTestApplicable();
        final int offset = 7;
        final int length = goodSignature_.length;
        final byte[] paddedSignature = new byte[3 * offset + length];
        // Ensure the padding isn't just 0s which might not trigger exceptions
        Arrays.fill(paddedSignature, (byte) 0x20);
        System.arraycopy(goodSignature_, 0, paddedSignature, offset, length);

        verifier_.update(message_);
        assertTrue(verifier_.verify(paddedSignature, offset, length));
    }

    @Test
    public void verifySingleByteBufferWrap() throws GeneralSecurityException {
        testSingleByteBuffer(false, applyParameters(ByteBuffer.wrap(message_)));
    }

    @Test
    public void verifySubByteBufferWrap() throws GeneralSecurityException {
        testSubByteBuffer(false, (position, length) -> applyParameters(ByteBuffer.wrap(message_, position, length)));
    }

    @Test
    public void verifySingleByteBuffer() throws GeneralSecurityException {
        final ByteBuffer bbuff = ByteBuffer.allocate(message_.length);
        bbuff.put(message_);
        bbuff.flip();
        testSingleByteBuffer(false, bbuff);
    }

    @Test
    public void verifySubByteBuffer() throws GeneralSecurityException {
        final ByteBuffer bbuff = ByteBuffer.allocate(message_.length);
        testSubByteBuffer(false, new BufferSplitter(bbuff));
    }

    @Test
    public void verifySingleByteBufferDirect() throws GeneralSecurityException {
        final ByteBuffer bbuff = ByteBuffer.allocate(message_.length);
        bbuff.put(message_);
        bbuff.flip();
        testSingleByteBuffer(false, applyParameters(bbuff));
    }

    @Test
    public void verifySubByteBufferDirect() throws GeneralSecurityException {
        final ByteBuffer bbuff = ByteBuffer.allocateDirect(message_.length);
        testSubByteBuffer(false, new BufferSplitter(bbuff));
    }

    @Test
    public void nullKeyYieldsInvalidKeyException() throws GeneralSecurityException {
        assertThrows(InvalidKeyException.class, () -> signer_.initSign(null));
        assertThrows(InvalidKeyException.class, () -> verifier_.initVerify((PublicKey) null));
    }

    @Test
    public void corruptedSignatureYieldsException() throws GeneralSecurityException {
        // JCA/JCE standards require that we try to throw an exception if the underlying signature is "corrupt" and not
        // just invalid.
        assumeFalse(algorithm_.contains("RSA")); // Does not apply to RSA algorithms
        assumeFalse(algorithm_.contains("inP1363Format")); // Does not apply to this format
        byte[] badSignature = goodSignature_.clone();
        for (int x = 0; x < badSignature.length; x++) {
            badSignature[x] ^= 0x5c; // Arbitrary value to twiddle the bits
        }

        assertThrows(SignatureException.class, () -> verifier_.verify(badSignature));
    }

    private void testSingleByteBuffer(boolean signMode, final ByteBuffer buff) throws GeneralSecurityException {
        final int oldLimit = buff.limit();
        if (signMode) {
            signer_.update(buff);
            jceVerifier_.update(message_);
            assertTrue(jceVerifier_.verify(signer_.sign()));
        } else {
            verifier_.update(buff);
            assertTrue(verifier_.verify(goodSignature_));
        }
        assertEquals("Buffer position isn't advanced.", buff.limit(), buff.position());
        assertEquals("Buffer limit incorrectly modified.", oldLimit, buff.limit());
    }

    private void testSubByteBuffer(boolean signMode, BiFunction<Integer, Integer, ByteBuffer> provider) throws GeneralSecurityException {
        final Signature sig = signMode ? signer_ : verifier_;
        for (final int length : LENGTHS) {
            if (length > message_.length) {
                break;
            }
            for (int x = 0; x < message_.length; x += length) {
                final int len = x + length > message_.length ? message_.length - x : length;
                final ByteBuffer buff = provider.apply(x,  len);
                final int oldLimit = buff.limit();
                sig.update(buff);
                assertEquals(String.format("Buffer position isn't advanced for position %d and length %d", x, length), buff.limit(), buff.position());
                assertEquals(String.format("Buffer position is incorrectly modified for position %d and length %d", x, length), oldLimit, buff.limit());
            }
            if (signMode) {
                jceVerifier_.update(message_);
                assertTrue(String.format("Signing fails for length %d", length), jceVerifier_.verify(signer_.sign()));
            } else {
                assertTrue(String.format("Verification fails for length %d", length), verifier_.verify(goodSignature_));
            }
        }
    }

    private final class BufferSplitter implements BiFunction<Integer, Integer, ByteBuffer> {
        final ByteBuffer baseBuffer_;

        public BufferSplitter(ByteBuffer baseBuffer) {
            baseBuffer_ = baseBuffer;
        }

        @Override
        public ByteBuffer apply(final Integer position, final Integer length) {
            baseBuffer_.position(position);
            baseBuffer_.limit(baseBuffer_.position() + length);
            baseBuffer_.put(message_, position, length);
            baseBuffer_.position(position);
            return applyParameters(baseBuffer_);
        }
    }

    private ByteBuffer applyParameters(final ByteBuffer buff) {
        ByteBuffer result = buff;
        if (readOnly_) {
            result = result.asReadOnlyBuffer();
        }
        if (slice_) {
            result = result.slice();
        }
        return result;
    }
}
