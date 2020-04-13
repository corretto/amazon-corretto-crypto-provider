// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.ECKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

abstract class EvpSignatureBase extends SignatureSpi {
    // Package visible so main Provider can use it
    static final String P1363_FORMAT_SUFFIX = "inP1363Format";
    protected static final int RSA_PKCS1_PADDING = 1;
    protected final EvpKeyType keyType_;
    protected final int paddingType_;
    protected Key key_ = null;
    protected byte[] keyDer_ = null;
    protected boolean signMode;
    protected int keyUsageCount_ = 0;
    protected EvpContext ctx_ = null;
    protected String algorithmName_ = null;

    EvpSignatureBase(
            final EvpKeyType keyType,
            final int paddingType
    ) {
        keyType_ = keyType;
        paddingType_ = paddingType;
    }

    protected abstract void engineReset();

    // Called reflectively upon creation
    void setAlgorithmName(String algorithmName) {
        this.algorithmName_ = algorithmName;
    }

    /**
     * Destroys the native context.
     *
     * @param ctx
     *            native context
     */
    private static native void destroyContext(long ctx);

    @Override
    protected synchronized void engineInitSign(final PrivateKey privateKey) throws InvalidKeyException {
        if (privateKey == null) {
            throw new InvalidKeyException("Key must not be null");
        }

        if (key_ != privateKey) {
            if (!keyType_.jceName.equalsIgnoreCase(privateKey.getAlgorithm())) {
                throw new InvalidKeyException();
            }
            keyUsageCount_ = 0;
            if (ctx_ != null) {
                ctx_.release();
                ctx_ = null;
            }
            key_ = privateKey;
            try {
                keyDer_ = keyType_.getKeyFactory().getKeySpec(privateKey, PKCS8EncodedKeySpec.class).getEncoded();
            } catch (final InvalidKeySpecException ex) {
                key_ = null;
                keyDer_ = null;
                throw new InvalidKeyException(ex);
            }
        }
        signMode = true;
        engineReset();
    }

    @Override
    protected synchronized void engineInitVerify(final PublicKey publicKey) throws InvalidKeyException {
        if (publicKey == null) {
            throw new InvalidKeyException("Key must not be null");
        }

        if (key_ != publicKey) {
            if (!keyType_.jceName.equalsIgnoreCase(publicKey.getAlgorithm())) {
                throw new InvalidKeyException();
            }
            keyUsageCount_ = 0;
            if (ctx_ != null) {
                ctx_.release();
                ctx_ = null;
            }
            key_ = publicKey;
            try {
                keyDer_ = keyType_.getKeyFactory().getKeySpec(publicKey, X509EncodedKeySpec.class).getEncoded();
            } catch (final InvalidKeySpecException ex) {
                key_ = null;
                keyDer_ = null;
                throw new InvalidKeyException(ex);
            }

        }
        signMode = false;
        engineReset();
    }

    @Override
    @Deprecated
    protected Object engineGetParameter(final String param) throws InvalidParameterException {
        throw new UnsupportedOperationException();
    }

    @Override
    @Deprecated
    protected void engineSetParameter(final String param, final Object value) throws InvalidParameterException {
        throw new UnsupportedOperationException();
    }

    @Override
    protected synchronized void engineSetParameter(final AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("No parameters supported by this algorithm");
        }
    }

    @Override
    protected synchronized AlgorithmParameters engineGetParameters() {
        return null;
    }

    /**
     * Ensures that we are properly initialized for the current mode of operation if specified.
     *
     * @param mode
     *            {@code true} if we're trying to sign data and {@code false} if we are trying to
     *            verify. If this value is {@code null} then it does not check to ensure it is
     *            initialized for a specific mode.
     * @throws SignatureException
     *             if we are not properly initialized
     */
    protected void ensureInitialized(final Boolean mode) throws SignatureException {
        // Code coverage is low as the java.security.Signature object actually
        // detects these cases before it reaches us.
        if (key_ == null) {
            throw new SignatureException("Not initialized");
        }
        if (mode != null && mode.booleanValue() != signMode) {
            throw new SignatureException("Incorrect mode for operation");
        }
    }

    protected static final class EvpContext extends NativeResource {
        protected EvpContext(final long ptr) {
            super(ptr, EvpSignatureBase::destroyContext);
        }
    }

    /**
     * Converts and returns the modified signature to verify <em>only if necessary</em> and returns {@code null} otherwise.
     * If {@code null} is returned then the passed in parameters should be used for later verification.
     * Otherwise, the entire returned array should be used.
     * This method has a somewhat odd API since we want to avoid unnecessary array copies/allocations and it is an
     * internal API anyway.
     *
     * @return the converted signature or {@code null} if no conversion is necessary
     * @throws SignatureException if the signature is badly malformed
     */
    protected byte[] maybeConvertSignatureToVerify(byte[] signature, int offset, int length) throws SignatureException {
        if (algorithmName_ != null && algorithmName_.endsWith(P1363_FORMAT_SUFFIX)) {
            final ECKey ecKey = (ECKey) key_;
            final int numLen = (ecKey.getParams().getOrder().bitLength() + 7) / 8;
            return ieeeP1363toAsn1(signature, offset, length, numLen);
        } else {
            return null;
        }
    }

    /**
     * Determines if we need to convert the signature <em>we generated</em> and performs said conversion.
     * <em>This methods may throw {@link AssertionError} on invalid input so should only be given trusted inputs.</em>.
     */
    protected byte[] maybeConvertSignatureToReturn(byte[] signature) throws SignatureException {
        if (algorithmName_ != null && algorithmName_.endsWith(P1363_FORMAT_SUFFIX)) {
            final ECKey ecKey = (ECKey) key_;
            final int numLen = (ecKey.getParams().getOrder().bitLength() + 7) / 8;
            return asn1ToiIeeeP1363(signature, numLen);
        } else {
            return signature;
        }
    }

    /**
     * This is a trivial conversion from two equal-length concatenated integers to an ASN.1 sequence.
     *
     * Since the resulting structure is so simple, we do not need a full ASN.1 engine and can cover all cases by hand.
     */
    protected static byte[] ieeeP1363toAsn1(byte[] signature, final int offset, final int length, int numLen) throws SignatureException {
        if (2 * numLen != length) {
            throw new SignatureException();
        }

        // This is the easiest way to trim unneeded zero-bytes
        final byte[] r = (new BigInteger(1, Arrays.copyOfRange(signature, offset, offset + numLen))).toByteArray();
        final byte[] s = (new BigInteger(1, Arrays.copyOfRange(signature, offset + numLen, offset + 2 * numLen))).toByteArray();

        if (r.length > 127 || s.length > 127) {
            throw new SignatureException("R or S value is too large");
        }

        // Encode the total sequence length. This might be one or two bytes
        final int seqLength = r.length + s.length + 4;
        final byte[] encodedSeqLength;
        if (seqLength <= 127) {
            encodedSeqLength = new byte[]{ (byte) (seqLength & 0xFF) };
        } else if (seqLength <= 256) {
            encodedSeqLength = new byte[]{ (byte) 0x81, (byte) (seqLength & 0xFF)};
        } else {
            throw new SignatureException("R or S value is too large");
        }

        final byte[] result = new byte[1 + encodedSeqLength.length + seqLength];
        int position = 0;
        result[position++] = 0x30; // SEQUENCE
        System.arraycopy(encodedSeqLength, 0, result, position, encodedSeqLength.length);
        position += encodedSeqLength.length;
        result[position++] = 0x02; // INTEGER
        result[position++] = (byte) (r.length & 0xFF); // Length of R
        System.arraycopy(r, 0, result, position, r.length);
        position += r.length;
        result[position++] = 0x02; // INTEGER
        result[position++] = (byte) (s.length & 0xFF); // Length of S
        System.arraycopy(s, 0, result, position, s.length);
        position += s.length;
        if (position != result.length) {
            throw new AssertionError("Final position of " + position + " does not match expected value of " + result.length);
        }

        return result;
    }

    /** Note: This should only be used on trusted inputs **/
    protected static byte[] asn1ToiIeeeP1363(byte[] signature, int numLen) throws SignatureException {
        // Check the ASN.1 for correctness and extract offsets
        int position = 0;
        if (signature[position++] != 0x30) {
            throw new AssertionError();
        }

        // Length may be one or two bytes
        int seqLen = Byte.toUnsignedInt(signature[position++]);
        if (seqLen == 0x81) {
            // Two byte length with second byte being the length
            seqLen = Byte.toUnsignedInt(signature[position++]);
        } else if (seqLen > 127) {
            // Unhandled long, reserved, or indefinite length
            throw new AssertionError();
        }
        if (seqLen != signature.length - position) {
            throw new AssertionError();
        }

        final int rOffset = position;
        if (signature[rOffset] != 0x02) {
            throw new AssertionError();
        }
        int rLen = Byte.toUnsignedInt(signature[rOffset + 1]);
        int rStart = rOffset + 2;

        final int sOffset = rStart + rLen;
        if (signature[sOffset] != 0x02) {
            throw new AssertionError(Base64.getEncoder().encodeToString(signature) + " : " +

                    String.format("%x, %x, %x", signature[sOffset - 1], signature[sOffset], signature[sOffset + 1]));
        }
        int sLen = Byte.toUnsignedInt(signature[sOffset + 1]);
        int sStart = sOffset + 2;

        // Remove leading zero bytes
        if (signature[rStart] == 0) {
            rStart++;
            rLen--;
        }
        if (signature[sStart] == 0) {
            sStart++;
            sLen--;
        }

        byte[] result = new byte[numLen * 2];
        System.arraycopy(signature, rStart, result, numLen - rLen, rLen);
        System.arraycopy(signature, sStart, result, numLen + numLen - sLen, sLen);
        return result;
    }
}
