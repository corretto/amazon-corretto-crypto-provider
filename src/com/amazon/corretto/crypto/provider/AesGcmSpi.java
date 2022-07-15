// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import static com.amazon.corretto.crypto.provider.Utils.EMPTY_ARRAY;

import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

final class AesGcmSpi extends CipherSpi {
    static {
        Loader.load();
    }

    /**
     * The number a times a key must be reused prior to keeping it in native memory rather than freeing it each time.
     **/
    private static final int KEY_REUSE_THRESHOLD = 1;

    private static final int DEFAULT_TAG_LENGTH = 16 * 8;

    /* Some random notes:
     * For decrypt mode, we buffer all data and process the decryption in doFinal;
     * this is because we cannot safely return only plaintext until we have validated
     * the tag at the end of the ciphertext.
     * Additionally, this matches JCE behavior.
     */

    private static final int NATIVE_MODE_ENCRYPT = 1;
    private static final int NATIVE_MODE_DECRYPT = 0;

    /**
     * Performs an encryption operation in a single call. AAD data is not supported in this mode. The native-side code
     * will take care of periodically dropping any buffer locks it has to allow GC to make progress.
     *
     * @param ctxPtr          Optional Context pointer
     * @param ctxPtrOut       Optional out parameter to recieve new context
     * @param input           Input plaintext to encrypt
     * @param inputOffset     Offset within input array of start of plaintext
     * @param inputLength     Data length to encrypt
     * @param result          Result array - must have room for inputLength + tagLen + resultOffset bytes
     * @param resultOffset    Offset of start of ciphertext in result array
     * @param tagLen          Length of GCM tag
     * @param key             AES key
     * @param iv              Initialization vector
     * @return Actual number of bytes written
     */
    private static native int oneShotEncrypt(
        long ctxPtr,
        long[] ctxPtrOut,
        byte[] input,
        int inputOffset,
        int inputLength,
        byte[] result,
        int resultOffset,
        int tagLen,
        byte[] key,
        byte[] iv
    );

    /**
     * Performs a decryption operation in a single call. Unlike oneShotEncrypt, AAD mode is supported. The native-side
     * code will take care of periodically dropping any buffer locks it has to allow GC to make progress.
     *
     * @param ctxPtr          Optional Context pointer
     * @param ctxPtrOut       Optional out parameter to recieve new context
     * @param input           Input plaintext to encrypt
     * @param inoffset        Offset within input array of start of plaintext
     * @param inlen           Data length to encrypt
     * @param result          Result array - must have room for inputLength + tagLen + resultOffset bytes
     * @param resultOffset    Offset of start of ciphertext in result array
     * @param tagLen          Length of GCM tag
     * @param key             AES key
     * @param iv              Initialization vector
     * @param aadBuffer       AAD data buffer; the data must start from offset zero in this buffer
     * @param aadSize         Size of AAD data; any data in the buffer beyond this point is ignored
     * @return Actual number of bytes written
     */
    private static native int oneShotDecrypt(
        long ctxPtr,
        long[] ctxPtrOut,
        byte[] input,
        int inoffset,
        int inlen,
        byte[] result,
        int resultOffset,
        int tagLen,
        byte[] key,
        byte[] iv,
        byte[] aadBuffer,
        int aadSize
    ) throws AEADBadTagException;

    /**
     * Initializes state for a non-one-shot encryption operation.
     *
     * @param key Encryption key
     * @param iv Initialization vector
     * @return Native pointer to context data structure, which must be freed using releaseContext() or encryptDoFinal()
     */
    private static native long encryptInit(byte[] key, byte[] iv);

    /**
     * Reuses an existing EVP context and initializes it for encryption given the new IV.
     *
     * @param ptr Context pointer
     * @param iv Initialization vector
     */
    private static native void encryptInit(long ptr, byte[] iv);

    /**
     * Processes some plaintext during a non-one-shot encryption operation. This is essentially a wrapper around
     * OpenSSL's EVP_CipherUpdate.
     *
     * @param ptr Context pointer
     * @param bytes Input data array
     * @param offset Offset within input array to start reading
     * @param length Number of plaintext bytes to process
     * @param output Output array
     * @param outputOffset Offset to start writing within output array
     * @return Actual number of bytes written
     */
    private static native int encryptUpdate(
        long ptr,
        byte[] bytes,
        int offset,
        int length,
        byte[] output,
        int outputOffset
    );

    /**
     * Provides some AAD data to a non-one-shot encryption operation.
     *
     * @param ptr Context pointer
     * @param bytes AAD data array
     * @param offset Start of AAD data within array
     * @param length Amount of AAD data to ingest
     */
    private static native void encryptUpdateAAD(long ptr, byte[] bytes, int offset, int length);

    /**
     * Finishes an encryption operation. This call will implicitly release the native context pointer, even if it fails
     * and throws an exception.
     *
     * @param ptr Native context pointer
     * @param  releaseContext if true releases the context
     * @param bytes Final input data (must not be null, even if no data is to be consumed)
     * @param offset Offset within bytes to start reading
     * @param length Length within bytes to read
     * @param output Output buffer
     * @param outputOffset Offset within output buffer to start writing
     * @param tagLen Length of GCM tag
     * @return Number of bytes written in this final operation
     */
    private static native int encryptDoFinal(
        long ptr,
        boolean releaseContext,
        byte[] bytes,
        int offset,
        int length,
        byte[] output,
        int outputOffset,
        int tagLen
    );

    /**
     * Aborts an encryption operation and releases native resources associated with it.
     *
     * @param ptr Native context pointer
     */
    private static native void releaseContext(long ptr);

    private static final int BLOCK_SIZE = 128 / 8;

    private final AmazonCorrettoCryptoProvider provider;
    private NativeResource context = null;
    private SecretKey jceKey;
    private byte[] iv, key;
    /** GCM tag length in bytes. */
    private int tagLength;
    private int opMode = -1;
    private boolean hasConsumedData = false;
    private boolean needReset = false;
    private int keyUsageCount = 0;
    private boolean contextInitialized = false;

    private final AccessibleByteArrayOutputStream decryptInputBuf = new AccessibleByteArrayOutputStream();
    private final AccessibleByteArrayOutputStream decryptAADBuf = new AccessibleByteArrayOutputStream();

    AesGcmSpi(final AmazonCorrettoCryptoProvider provider) {
        Loader.checkNativeLibraryAvailability();
        this.provider = provider;
    }

    @Override
    protected void engineSetMode(final String s) throws NoSuchAlgorithmException {
        if (!"GCM".equalsIgnoreCase(s)) {
            throw new NoSuchAlgorithmException();
        }
    }

    @Override
    protected void engineSetPadding(final String s) throws NoSuchPaddingException {
        if (!"NoPadding".equalsIgnoreCase(s)) {
            throw new NoSuchPaddingException();
        }
    }

    @Override
    protected int engineGetBlockSize() {
        return BLOCK_SIZE;
    }

    @Override
    protected int engineGetKeySize(final Key key) throws InvalidKeyException {
        return key.getEncoded().length * 8;
    }

    @Override
    protected int engineGetOutputSize(final int inputLen) {
        switch (opMode) {
            case NATIVE_MODE_ENCRYPT:
                return getUpdateOutputSize(inputLen) + tagLength;
            case NATIVE_MODE_DECRYPT:
                return Math.max(0, decryptInputBuf.size() + inputLen - tagLength);
            default:
                throw new IllegalStateException("Cipher not initialized");
        }
    }

    /* Returns the maximum amount of data that could be returned from an update (not doFinal) operation.
     * Not exposed via the Cipher API, but used internally to allocate buffers to return to the caller.
     */
    private int getUpdateOutputSize(final int inputLen) {
        switch (opMode) {
            case NATIVE_MODE_ENCRYPT:
                return inputLen;
            case NATIVE_MODE_DECRYPT:
                // We do not return data from engineUpdate when decrypting - all data is returned from engineDoFinal()
                return 0;
            default:
                throw new IllegalStateException("Cipher not initialized");
        }
    }

    @Override
    protected byte[] engineGetIV() {
        return iv.clone();
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("GCM");
            parameters.init(new GCMParameterSpec(tagLength * 8, iv));
            return parameters;
        } catch (InvalidParameterSpecException | NoSuchAlgorithmException e) {
            throw new Error("Unexpected error", e);
        }
    }

    @Override
    protected void engineInit(final int opMode, final Key key, final SecureRandom secureRandom)
            throws InvalidKeyException {
        if (opMode != Cipher.ENCRYPT_MODE && opMode != Cipher.WRAP_MODE) {
            throw new InvalidKeyException("IV required for decrypt");
        }

        final byte[] iv = new byte[12];
        secureRandom.nextBytes(iv);

        try {
            engineInit(opMode, key, new GCMParameterSpec(DEFAULT_TAG_LENGTH, iv), secureRandom);
        } catch (InvalidAlgorithmParameterException e) {
            throw new AssertionError(e);
        }
    }

    @Override
    protected void engineInit(
        final int jceOpMode,
        final Key key,
        final AlgorithmParameterSpec algorithmParameterSpec,
        final SecureRandom secureRandom
    ) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (key == null) {
            throw new InvalidKeyException("Key can't be null");
        }

        final GCMParameterSpec spec;
        if (algorithmParameterSpec instanceof GCMParameterSpec) {
            spec = (GCMParameterSpec) algorithmParameterSpec;
        } else if (algorithmParameterSpec instanceof IvParameterSpec) {
            spec = new GCMParameterSpec(DEFAULT_TAG_LENGTH,
                    ((IvParameterSpec) algorithmParameterSpec).getIV());
        } else {
            throw new InvalidAlgorithmParameterException(
                "I don't know how to handle a " + algorithmParameterSpec.getClass());
        }

        byte[] encodedKey = null;
        if (jceKey != key) {
            if (!(key instanceof  SecretKey)) {
                throw new InvalidKeyException("Need a SecretKey");
            }
            String keyAlgorithm = key.getAlgorithm();
            if (!"RAW".equalsIgnoreCase(key.getFormat())) {
                throw new InvalidKeyException("Need a raw format key");
            }
            if (!keyAlgorithm.equalsIgnoreCase("AES")) {
                throw new InvalidKeyException("Expected an AES key");
            }
            encodedKey = key.getEncoded();
            if (encodedKey == null) {
                throw new InvalidKeyException("Key doesn't support encoding");
            }

            if (!MessageDigest.isEqual(encodedKey, this.key)) {
                if (encodedKey.length != 128 / 8 && encodedKey.length != 192 / 8 && encodedKey.length != 256 / 8) {
                    throw new InvalidKeyException("Bad key length of " + (encodedKey.length * 8)
                        + " bits; expected 128, 192, or 256 bits");
                }

                keyUsageCount = 0;
                if (context != null) {
                    context.release();
                }

                context = null;
            } else {
                encodedKey = null;
            }
        }

        final byte[] iv = spec.getIV();

        if ((spec.getTLen() % 8 != 0) || spec.getTLen() > 128 || spec.getTLen() < 96) {
            throw new InvalidAlgorithmParameterException(
                "Unsupported TLen value; must be one of {128, 120, 112, 104, 96}");
        }


        if (this.iv != null && this.key != null
                && (jceOpMode == Cipher.ENCRYPT_MODE || jceOpMode == Cipher.WRAP_MODE)) {
            if (Arrays.equals(this.iv, iv) && (encodedKey == null || MessageDigest.isEqual(this.key, encodedKey))) {
                throw new InvalidAlgorithmParameterException("Cannot reuse same iv and key for GCM encryption");
            }
        }

        if (iv == null || iv.length == 0) {
            throw new InvalidAlgorithmParameterException("IV must be at least one byte long");
        }

        switch (jceOpMode) {
            case Cipher.ENCRYPT_MODE:
            case Cipher.WRAP_MODE:
                this.opMode = NATIVE_MODE_ENCRYPT;
                break;
            case Cipher.DECRYPT_MODE:
            case Cipher.UNWRAP_MODE:
                this.opMode = NATIVE_MODE_DECRYPT;
                break;
            default:
                throw new InvalidAlgorithmParameterException("Unsupported cipher mode " + jceOpMode);
        }


        this.iv = iv;
        this.tagLength = spec.getTLen() / 8;
        if (encodedKey != null) {
            this.key = encodedKey;
            this.jceKey = (SecretKey) key;
        }
        this.needReset = false;

        stateReset();
    }

    @Override
    protected void engineInit(
        int opMode, Key key, AlgorithmParameters algorithmParameters, SecureRandom secureRandom
    ) throws InvalidKeyException, InvalidAlgorithmParameterException {
        try {
            engineInit(opMode, key, algorithmParameters.getParameterSpec(GCMParameterSpec.class), secureRandom);
        } catch (InvalidParameterSpecException e) {
            throw new InvalidAlgorithmParameterException(e);
        }
    }

    @Override
    protected byte[] engineUpdate(byte[] bytes, int offset, int length) {
        byte[] buf = new byte[getUpdateOutputSize(length)];

        int actualLength;
        try {
            actualLength = engineUpdate(bytes, offset, length, buf, 0);
        } catch (ShortBufferException e) {
            throw new AssertionError(e);
        }

        if (actualLength == buf.length) {
            return buf;
        } else {
            return Arrays.copyOf(buf, actualLength);
        }
    }

    @Override
    protected int engineUpdate(byte[] bytes, int offset, int length, byte[] output, int outputOffset) throws ShortBufferException {
        checkArrayLimits(bytes, offset, length);

        hasConsumedData = true;

        switch (opMode) {
            case NATIVE_MODE_DECRYPT:
            {
                decryptInputBuf.write(bytes, offset, length);
                return 0;
            }
            case NATIVE_MODE_ENCRYPT:
            {
                checkOutputBuffer(length, output, outputOffset);

                lazyInit();

                // If we have an overlap, we'll need to clone the input buffer before we potentially start overwriting
                // it.
                final byte[] finalBytes;
                final int finalOffset;
                if (Utils.arraysOverlap(bytes, offset, output, outputOffset, engineGetOutputSize(length))) {
                    finalBytes = Arrays.copyOfRange(bytes, offset, offset + length);
                    finalOffset = 0;
                } else {
                    finalBytes = bytes;
                    finalOffset = offset;
                }

                return context.use(ptr->encryptUpdate(ptr, finalBytes, finalOffset, length, output, outputOffset));
            }
            default:
                throw new IllegalStateException("Cipher not initialized");
        }
    }

    @Override
    protected void engineUpdateAAD(byte[] bytes, int offset, int length) {
        checkArrayLimits(bytes, offset, length);

        if (hasConsumedData) {
            throw new IllegalStateException("AAD data cannot be updated after calling update()");
        }

        // Older (<= 1.0.1) versions of openssl don't allow AAD data to be provided before the AEAD tag
        if (opMode == NATIVE_MODE_DECRYPT) {
            decryptAADBuf.write(bytes, offset, length);
            return;
        }

        lazyInit();

        internalUpdateAAD(bytes, offset, length);
    }

    private void internalUpdateAAD(byte[] bytes, int offset, int length) {
        while (length > 0) {
            final int stepLength = Math.min(length, 512 * 1024);
            final int finalOffset = offset;

            context.useVoid(ptr->encryptUpdateAAD(ptr, bytes, finalOffset, stepLength));

            offset += stepLength;
            length -= stepLength;
        }
    }

    @Override
    protected void engineUpdateAAD(ByteBuffer byteBuffer) {
        if (byteBuffer.hasArray()) {
            engineUpdateAAD(byteBuffer.array(), byteBuffer.arrayOffset() + byteBuffer.position(), byteBuffer.remaining());
        } else {
            byte[] tmp = new byte[byteBuffer.remaining()];
            byteBuffer.get(tmp);

            engineUpdateAAD(tmp, 0, tmp.length);
        }

        byteBuffer.position(byteBuffer.limit());
    }

    // We split our final handling of encryption and decryption into two separate methods because they have different
    // requirements and we can optimize them differently.
    // Encryption can be done in an online/streaming manner which allows us to write directly to the output array
    // provided by external callers.
    // Decryption is always done as a single call which requires us to allocate an array to receive the plaintext
    // until we can validate its correctness.
    private int engineEncryptFinal(
            byte[] input,
            final int offset,
            int length,
            final byte[] output,
            int outputOffset) throws ShortBufferException {
        try {
            if (opMode != NATIVE_MODE_ENCRYPT) {
                throw new IllegalStateException("Cipher not initialized for encryption");
            }
            if (input == null) {
                input = EMPTY_ARRAY;
            }

            checkOutputBuffer(length, output, outputOffset);
            checkArrayLimits(input, offset, length);

            final boolean overlaps = Utils.arraysOverlap(
                input, offset, output, outputOffset, Math.max(length, engineGetOutputSize(length)));

            int resultLength = 0;

            if (overlaps) {
                // The input and output potentially overlap. We'll need to make sure we copy the input somewhere safe before
                // proceeding too much further.
                // TODO: Further optimize by handling the safe case when both input and output start
                // at exactly the same place.

                // Since we need to take care of this on engineUpdate as well, we can just delegate to engineUpdate, which
                // will make sure to copy the buffer - on encrypt this is an explicit check, while on decrypt engineUpdate
                // unconditionally copies to a temporary buffer.

                resultLength = engineUpdate(input, offset, length, output, outputOffset);
                outputOffset += resultLength;

                // We processed all of the input in engineUpdate. So there's no longer an overlap to deal with.
                length = 0;
            }

            checkNeedReset();

            this.needReset = true;
            final byte[] finalInput = input;
            final int finalInputLength = length;
            final int finalOutputOffset = outputOffset;

            if (!contextInitialized) {
                // Context has not been initialized, meaning the user called doFinal immediately after init(). In this case
                // we make a single native call to perform the encryption operation in one go.

                keyUsageCount++;
                if (context != null) {
                    // Our key, but not our IV has been initialized
                    return context.use(ptr -> {
                        return oneShotEncrypt(
                                ptr,
                                null,
                                finalInput,
                                offset,
                                finalInputLength,
                                output,
                                finalOutputOffset,
                                tagLength,
                                key,
                                iv
                        );
                    });
                } else {
                    // We don't have an existing context, however we might want to save one
                    final long[] ptrOut = keyUsageCount > KEY_REUSE_THRESHOLD ? new long[1] : null;
                    final int outLen = oneShotEncrypt(
                            0,
                            ptrOut,
                            finalInput,
                            offset,
                            finalInputLength,
                            output,
                            finalOutputOffset,
                            tagLength,
                            key,
                            iv
                    );
                    if (ptrOut != null) {
                        context = new NativeContext(ptrOut[0]);
                    }
                    return outLen;
                }
            } else {
                // We need to make sure to add resultLength here; engineUpdate in encrypt mode produces incremental
                // output (unlike in decrypt mode) and so we need to carry forward whatever amount of data it produced
                // in our return value.

                keyUsageCount++;

                final int finalOutputLen;

                if (keyUsageCount > KEY_REUSE_THRESHOLD) {
                    finalOutputLen = context.use(ptr ->
                            encryptDoFinal(
                            ptr,
                            false, // releaseContext
                            finalInput,
                            offset,
                            finalInputLength,
                            output,
                            finalOutputOffset,
                            tagLength
                    ));
                } else {
                    finalOutputLen =
                        encryptDoFinal(
                                context.take(),
                                true, // releaseContext
                                input,
                                offset,
                                finalInputLength,
                                output,
                                finalOutputOffset,
                                tagLength
                        );
                    context = null;
                }
                return resultLength + finalOutputLen;
            }
        } finally {
            stateReset();
        }
    }

    private byte[] engineDecryptFinal(byte[] input, final int offset, final int length) throws AEADBadTagException {
        try {
            if (opMode != NATIVE_MODE_DECRYPT) {
                throw new IllegalStateException("Cipher not initialized for decryption");
            }
            if (input == null) {
                input = EMPTY_ARRAY;
            }

            // If we already have processed some amount of ciphertext then we must coallesce it prior to decryption.
            // Otherwise, we can just use the provided input.
            final byte[] workingInputArray;
            final int workingInputOffset;
            final int workingInputLength;
            if (decryptInputBuf.size() > 0) {
                // We've already processed data so need to merge this in
                engineUpdate(input, offset, length); // Decrypt mode never generates output for updates
                workingInputArray = decryptInputBuf.getDataBuffer();
                workingInputLength = decryptInputBuf.size();
                workingInputOffset = 0;
            } else {
                workingInputArray = input;
                workingInputLength = length;
                workingInputOffset = offset;
            }

            if (workingInputLength < tagLength) {
                throw new AEADBadTagException("Input too short - need tag");
            }

            final int expectedOutputLength = workingInputLength - tagLength;
            final byte[] result = new byte[expectedOutputLength];

            keyUsageCount++;
            final int outLen;
            if (context != null) {
                // We already have a context, so let's reuse it.
                outLen = context.use(ptr -> {
                    return oneShotDecrypt(
                            ptr,
                            null,
                            workingInputArray,
                            workingInputOffset,
                            workingInputLength,

                            result,
                            0,

                            tagLength,
                            key,
                            iv,

                            // The cost of calling decryptAADBuf.getDataBuffer() when its buffer is empty is significant for 16-byte
                            // decrypt operations (approximately a 7% performance hit). To avoid this, we reuse the same empty array
                            // instead in this common-case path.
                            decryptAADBuf.size() != 0 ? decryptAADBuf.getDataBuffer() : EMPTY_ARRAY,
                            decryptAADBuf.size()
                    );
                });
            } else {
                // We don't have an existing context, however we might want to save one
                final long[] ptrOut = keyUsageCount > KEY_REUSE_THRESHOLD ? new long[1] : null;
                outLen = oneShotDecrypt(
                        0,
                        ptrOut,
                        workingInputArray,
                        workingInputOffset,
                        workingInputLength,

                        result,
                        0,

                        tagLength,
                        key,
                        iv,

                        // The cost of calling decryptAADBuf.getDataBuffer() when its buffer is empty is significant for 16-byte
                        // decrypt operations (approximately a 7% performance hit). To avoid this, we reuse the same empty array
                        // instead in this common-case path.
                        decryptAADBuf.size() != 0 ? decryptAADBuf.getDataBuffer() : EMPTY_ARRAY,
                        decryptAADBuf.size()
                );

                if (ptrOut != null) {
                    context = new NativeContext(ptrOut[0]);
                }
            }
            // Decryption completed successfully.
            if (outLen == result.length) {
                // This should always be the case.
                return result;
            } else if (outLen < result.length) {
                // While technically allowed by the APIs, this should never happen.
                return Arrays.copyOf(result, outLen);
            } else {
                throw new RuntimeCryptoException("Output longer than expected.");
            }
        } finally {
            stateReset();
        }
    }

    @Override
    protected byte[] engineDoFinal(byte[] bytes, int offset, int length)
            throws IllegalBlockSizeException, BadPaddingException {
        if (opMode == NATIVE_MODE_ENCRYPT) {
            final byte[] buf = new byte[engineGetOutputSize(length)];
            int actualLength;
            try {
                actualLength = engineEncryptFinal(bytes, offset, length, buf, 0);
            } catch (ShortBufferException e) {
                throw new AssertionError(e);
            }

            if (actualLength == buf.length) {
                return buf;
            } else {
                // This branch should never happen but is technically allowed by the underlying APIs.
                // So, we cover it just in case.
                return Arrays.copyOf(buf, actualLength);
            }
        } else if (opMode == NATIVE_MODE_DECRYPT) {
            return engineDecryptFinal(bytes, offset, length);
        } else {
            throw new IllegalStateException("Cipher not initialized");
        }
    }

    @Override
    protected int engineDoFinal(
        byte[] input, final int offset, final int length, final byte[] output, final int outputOffset)
        throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
    {
        if (input == null) {
            input = EMPTY_ARRAY;
        }
        checkOutputBuffer(length, output, outputOffset);
        checkArrayLimits(input, offset, length);
        if (opMode == NATIVE_MODE_DECRYPT) {
            final byte[] plaintext = engineDecryptFinal(input, offset, length);
            System.arraycopy(plaintext, 0, output, outputOffset, plaintext.length);
            return plaintext.length;
        } else if (opMode == NATIVE_MODE_ENCRYPT) {
            return engineEncryptFinal(input, offset, length, output, outputOffset);
        } else {
            throw new IllegalStateException("Cipher not initialized");
        }
    }

    @Override
    protected byte[] engineWrap(final Key key) throws IllegalBlockSizeException, InvalidKeyException {
        if (opMode != NATIVE_MODE_ENCRYPT) {
            throw new IllegalStateException("Cipher must be in WRAP_MODE");
        }
        try {
            final byte[] encoded = Utils.encodeForWrapping(provider, key);
            return engineDoFinal(encoded, 0, encoded.length);
        } catch (final BadPaddingException ex) {
            throw new InvalidKeyException("Wrapping failed", ex);
        }
    }

    @Override
    protected Key engineUnwrap(final byte[] wrappedKey, final String wrappedKeyAlgorithm, final int wrappedKeyType)
            throws InvalidKeyException, NoSuchAlgorithmException {
        if (opMode != NATIVE_MODE_DECRYPT) {
            throw new IllegalStateException("Cipher must be in UNWRAP_MODE");
        }
        try {
            final byte[] unwrappedKey = engineDoFinal(wrappedKey, 0, wrappedKey.length);
            return Utils.buildUnwrappedKey(provider, unwrappedKey, wrappedKeyAlgorithm, wrappedKeyType);
        } catch (final BadPaddingException | IllegalBlockSizeException | InvalidKeySpecException ex) {
            throw new InvalidKeyException("Unwrapping failed", ex);
        }
    }

    private static final class NativeContext extends NativeResource {
        private NativeContext(final long ptr) {
            super(ptr, AesGcmSpi::releaseContext);
        }
    }

    /**
     * An array view over a bytebuffer - either directly aliasing the underlying bytebuffer, or a copy of the byte
     * buffer's data. In the latter case, writeback() will copy the data back to the original byte buffer after
     * modifications have been made.
     */
    private static final class ShimArray {
        private final ByteBuffer backingBuffer;
        private final boolean doWriteback;
        public final byte[] array;
        public final int offset, length;

        private ShimArray(final ByteBuffer buffer, final int length) {
            this.backingBuffer = buffer.duplicate();

            boolean hasArray = backingBuffer.hasArray();
            byte[] tmpArray = hasArray ? backingBuffer.array() : null;
            if (tmpArray == null) {
                tmpArray = new byte[length];
                backingBuffer.duplicate().get(tmpArray);
                doWriteback = true;
                offset = 0;
            } else {
                doWriteback = false;
                offset = backingBuffer.arrayOffset() + backingBuffer.position();
            }

            this.array = tmpArray;
            this.length = length;
        }

        private void writeback() {
            if (doWriteback) {
                backingBuffer.duplicate().put(array);
            }
        }
    }

    @Override
    protected int engineUpdate(ByteBuffer input, final ByteBuffer output)
            throws ShortBufferException {
        ByteBuffer bufferForClear = null;

        // The default JCE implementation of this bytebuffer-to-byte[] shim seems to break when engineGetOutputSize
        // returns more bytes then is actually used in each round (it only calls engineGetOutputSize once, on the entire
        // input size, and does not properly size the output buffer for each round). By coincidence this works as long
        // as the cipher actually knows how much space it's going to use for its bounds checking and the actual buffer
        // sizes for input and output match the cipher block size - but in our case we don't know what EVP's going to do
        // and have to be conservative, requiring a larger output than input buffer. So we have to implement this loop
        // ourselves.

        int initialPosition = output.position();

        if (output.remaining() < engineGetOutputSize(input.remaining())) {
            throw new ShortBufferException();
        }

        if (Utils.buffersMaybeOverlap(input, output)) {
            // We'll just copy the whole input buffer if it might overlap with output.
            // It's possible to do something more efficient for a couple of special cases here, but we'll do the simple
            // and safe thing for now.
            ByteBuffer newInput = ByteBuffer.allocate(input.remaining());
            newInput.put(input);
            newInput.flip();
            input = newInput;
            bufferForClear = input;
        }

        while (input.hasRemaining()) {
            int inputChunkSize = Math.min(input.remaining(), 65536);

            ShimArray inputArray = new ShimArray(input, inputChunkSize);
            ShimArray outputArray = new ShimArray(output, engineGetOutputSize(inputChunkSize));

            int outputBytes = engineUpdate(
                inputArray.array, inputArray.offset, inputArray.length,
                outputArray.array, outputArray.offset);
            outputArray.writeback();

            input.position(input.position() + inputChunkSize);
            output.position(output.position() + outputBytes);
        }

        // If we copied the input, make a best effort attempt to clear the buffer.
        if (bufferForClear != null) {
            Utils.zeroByteBuffer(bufferForClear);
        }

        return output.position() - initialPosition;
    }

    @Override
    protected int engineDoFinal(final ByteBuffer input, final ByteBuffer output)
        throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
    {
        int initialPosition = output.position();

        engineUpdate(input, output);

        ShimArray shim = new ShimArray(output, engineGetOutputSize(0));
        int finalBytes = engineDoFinal(EMPTY_ARRAY, 0, 0, shim.array, shim.offset);

        shim.writeback();
        output.position(output.position() + finalBytes);

        return output.position() - initialPosition;
    }

    private void checkOutputBuffer(final int inputLength, final byte[] output, final int outputOffset)
            throws ShortBufferException {
        if (inputLength < 0 || outputOffset < 0 || outputOffset > output.length) {
            throw new ArrayIndexOutOfBoundsException();
        }
        if (output.length - outputOffset < getUpdateOutputSize(inputLength)) {
            throw new ShortBufferException("Expected a buffer of at least "
                + engineGetOutputSize(inputLength) + " bytes; got " + (output.length - outputOffset));
        }
    }

    private void checkArrayLimits(final byte[] bytes, final int offset, final int length) {
        if (offset < 0 || length < 0) {
            throw new ArrayIndexOutOfBoundsException("Negative offset or length");
        }

        if ((long) offset + (long) length > bytes.length) {
            throw new ArrayIndexOutOfBoundsException("Requested range is outside of buffer limits");
        }
    }

    // @GuardedBy("this") // Restore once replacement for JSR-305 available
    private void lazyInit() {
        if (contextInitialized) {
            return;
        }
        contextInitialized = true;
        if (opMode < 0) {
            throw new IllegalStateException("Cipher not initialized");
        }

        checkNeedReset();

        if (context != null) {
            context.useVoid(ptr -> encryptInit(ptr, iv));
        } else {
            long ptr = encryptInit(key, iv);

            context = new NativeContext(ptr);
        }
    }

    /**
     * Throws {@link IllegalStateException} if we're about to do a second encrypt call
     * without changing either the key or IV.
     */
    private void checkNeedReset() {
        if (needReset) {
            throw new IllegalStateException("Must change key or IV for GCM mode encryption");
        }
    }

    // @GuardedBy("this") // Restore once replacement for JSR-305 available
    private void stateReset() {
        // While this shouldn't happen, we cover this case to ensure we return to a good state.
        if (context != null && context.isReleased()) {
            context = null;
        }
        decryptInputBuf.reset();
        decryptAADBuf.reset();

        hasConsumedData = false;
        contextInitialized = false;
    }

}
