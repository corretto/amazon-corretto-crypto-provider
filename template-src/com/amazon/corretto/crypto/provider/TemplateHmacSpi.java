// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import static java.util.logging.Logger.getLogger;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.Mac;
import javax.crypto.MacSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.amazon.corretto.crypto.provider.AesCtrDrbg.SPI;

public class TemplateHmacSpi extends MacSpi implements Cloneable {
    private static final String MAC_NAME = "Hmac@@@SHORT_HASH_NAME@@@";
    private static final int HASH_SIZE;
    private static final int BLOCK_SIZE;

    static final SelfTestSuite.SelfTest SELF_TEST = new SelfTestSuite.SelfTest(MAC_NAME, TemplateHmacSpi::runSelfTest);

    private static final byte[] INITIAL_CONTEXT;
    private static Throwable selfTestThrowable = null;

    /**
     * Returns the required size in bytes of the context object.
     */
    private static native int getContextSize();

    /**
     * Returns the size of the underlying blocks within the hash.
     */
    private static native int getBlockSize();

    /**
     * Returns the output size of the underlying hash (and thus of this MAC).
     */
    private static native int getHashSize();

    /**
     * Given an array of exactly {@link #getContextSize()} bytes, initializes it.
     */
    private static native void initContext(byte[] ctx);

    // Note: All following native methods assume that normalKey has the correctLength of {@link #BLOCK_SIZE}.

    /**
     * Updates the provided context with the data specifried by {@code src}. The {@code key} is
     * optional and must be provided <em>only</em> for the initial {@code update*} call (whether
     * {@link #updateCtxArray(byte[], byte[], byte[], int, int)} or
     * {@link #updateCtxBuffer(byte[], byte[], ByteBuffer)}). All subsequent calls <em>must</em> set
     * this parameter to null.
     * 
     * @param ctx
     *            the context (previously initialized by {@link #initContext(byte[])}
     * @param normalKey
     *            The HMAC normalKey <em>only</em> for the initial call to an update method and
     *            {@code null} for all other updates.
     * @param src
     *            data the be included in the HMAC
     * @param offset
     *            offset into {@code src} for the input data
     * @param length
     *            length of the data in {@code src} to be included in the HMAC.
     */
    private static native void updateCtxArray(byte[] ctx, byte[] normalKey, byte[] src, int offset,
            int length);
    private static void synchronizedUpdateCtxArray(byte[] ctx, byte[] normalKey, byte[] src, int offset, int length) {
        synchronized (ctx) {
            updateCtxArray(ctx, normalKey, src, offset, length);
        }
    }

    /**
     * Updates the provided context with the data specifried by {@code src}. The {@code key} is
     * optional and must be provided <em>only</em> for the initial {@code update*} call (whether
     * {@link #updateCtxArray(byte[], byte[], byte[], int, int)} or
     * {@link #updateCtxBuffer(byte[], byte[], ByteBuffer)}). All subsequent calls <em>must</em> set
     * this parameter to null.
     * 
     * @param ctx
     *            the context (previously initialized by {@link #initContext(byte[])}
     * @param normalKey
     *            The HMAC normalKey <em>only</em> for the initial call to an update method and
     *            {@code null} for all other updates.
     * @param src
     *            data the be included in the HMAC
     */
    private static native void updateCtxBuffer(byte[] ctx, byte[] normalKey, ByteBuffer src);
    private static void synchronizedUpdateCtxBuffer(byte[] ctx, byte[] normalKey, ByteBuffer src) {
        synchronized (ctx) {
            updateCtxBuffer(ctx, normalKey, src);
        }
    }

    /**
     * Finishes calculating and returns the HMAC in {@code result}.
     * 
     * @param ctx
     *            the context (previously initialized by {@link #initContext(byte[])}
     * @param normalKey
     *            the HMAC oKey
     * @param result
     *            an array of length {@link #getContextSize()} to receive the HMAC result
     */
    private static native void doFinal(byte[] ctx, byte[] normalKey, byte[] result);
    private static void synchronizedDoFinal(byte[] ctx, byte[] normalKey, byte[] result) {
        synchronized (ctx) {
            doFinal(ctx, normalKey, result);
        }
    }

    private static native void fastHmac(byte[] normalKey, byte[] message, int offset, int length,
            byte[] result);

    static {
        INITIAL_CONTEXT = new byte[getContextSize()];
        initContext(INITIAL_CONTEXT);
        HASH_SIZE = getHashSize();
        BLOCK_SIZE = getBlockSize();
    }

    @SuppressWarnings("serial")
    private static class TestMacProvider extends Provider {
        // The superconstructor taking a double version is deprecated in java 9. However, the replacement for it is
        // unavailable in java 8, so to build on both with warnings on our only choice is suppress deprecation warnings.
        @SuppressWarnings({"deprecation"})
        protected TestMacProvider() {
            super("test provider", 0, "internal self-test provider");
        }

        @Override public synchronized Service getService(final String type, final String algorithm) {
            if (type.equals("Mac") && algorithm.equals(MAC_NAME)) {
                return new Service(this, type, algorithm, TemplateHmacSpi.class.getName(), Collections.emptyList(), Collections.emptyMap()) {
                    @Override public Object newInstance(final Object constructorParameter) {
                        return new TemplateHmacSpi(true);
                    }
                };
            } else {
                return super.getService(type, algorithm);
            }
        }
    }

    public static SelfTestResult runSelfTest() {
        Provider p = new TestMacProvider();

        int tests = 0;
        // Some of this weird logic is so that templated code doesn't have absolutely terrible
        // coverage. I feel bad about this but it's only in the self-test and will go away once
        // we eliminate the templates.
        final Map<String, String> hashCategory = new HashMap<>();
        final Map<String, Integer> hashLocation = new HashMap<>();
        hashCategory.put("HmacMD5", "md5");
        hashLocation.put("HmacMD5", 0);
        hashCategory.put("HmacSHA1", "sha1");
        hashLocation.put("HmacSHA1", 0);
        hashCategory.put("HmacSHA256", "sha2");
        hashLocation.put("HmacSHA256", 0);
        hashCategory.put("HmacSHA384", "sha2");
        hashLocation.put("HmacSHA384", 1);
        hashCategory.put("HmacSHA512", "sha2");
        hashLocation.put("HmacSHA512", 2);

        try (final Scanner in = new Scanner(Loader.getTestData("hmac.txt"), StandardCharsets.US_ASCII.name())) {
            final Mac testMac = Mac.getInstance(MAC_NAME, p);
            while (in.hasNext()) {
                tests++;
                final String type = in.next();
                SecretKey key = new SecretKeySpec(Utils.decodeHex(in.next()), MAC_NAME);
                byte[] message = Utils.decodeHex(in.next());
                String[] expecteds = in.nextLine().trim().split("\\s+");
                if (type.equals(hashCategory.get(MAC_NAME))) {
                    Utils.testMac(testMac, key, message, Utils.decodeHex(expecteds[hashLocation.get(MAC_NAME)]));
                }
            }
            return new SelfTestResult(SelfTestStatus.PASSED);
        } catch (Throwable ex) {
            getLogger("AmazonCorrettoCryptoProvider").severe(MAC_NAME + " failed self-test " + tests);
            return new SelfTestResult(ex);
        }
    }

    private static class State {
        /** Contains the HMAC key after being normalized to length @{link BLOCK_SIZE} **/
        final byte[] normalKey = new byte[BLOCK_SIZE];
        final byte[] ctx = INITIAL_CONTEXT.clone();
        boolean initialized = false;

        public void setKey(final byte[] key) {
            Arrays.fill(normalKey, (byte) 0);
            if (key.length > BLOCK_SIZE) {
                TemplateHashSpi.fastDigest(normalKey, key, key.length);
            } else {
                System.arraycopy(key, 0, normalKey, 0, key.length);
            }
            initialized = true;
        }

        public void reset() {
            System.arraycopy(INITIAL_CONTEXT, 0, ctx, 0, INITIAL_CONTEXT.length);
        }

        /*
         * We aren't bothering with clone() because this is a very simple object with lots of final fields.
         */
        public State copy() {
            State result = new State();
            System.arraycopy(normalKey, 0, result.normalKey, 0, normalKey.length);
            System.arraycopy(ctx, 0, result.ctx, 0, ctx.length);
            result.initialized = initialized;
            return result;
        }
    }

    // None of these fields are final so that we can clone them.
    private byte[] oneByteArray = null;
    private State baseState = new State();
    private InputBuffer<byte[], Void> buffer;


    public TemplateHmacSpi() {
        this(false);
    }

    private TemplateHmacSpi(boolean inSelfTest) {
        if (!inSelfTest) {
            SELF_TEST.assertSelfTestPassed();
        }
        buffer = setLambdas(new InputBuffer<byte[], Void>(1024));
    }

    private InputBuffer<byte[], Void> setLambdas(InputBuffer<byte[], Void> buffer) {
        return buffer.withInitialUpdater((src, offset, length) -> {
            assertInitialized();
            synchronizedUpdateCtxArray(baseState.ctx, baseState.normalKey, src, offset, length);
            return null;
        })
        .withInitialUpdater((src) -> {
             assertInitialized();
             synchronizedUpdateCtxBuffer(baseState.ctx, baseState.normalKey, src);
             return null;
        })
        .withUpdater((ignored, src, offset, length) -> {
            assertInitialized();
            synchronizedUpdateCtxArray(baseState.ctx, null, src, offset, length);
        })
        .withUpdater((ignored, src) -> {
            assertInitialized();
            synchronizedUpdateCtxBuffer(baseState.ctx, null, src);
        })
        .withDoFinal((ignored) -> {
            assertInitialized();
            final byte[] result = new byte[HASH_SIZE];
            synchronizedDoFinal(baseState.ctx, baseState.normalKey, result);
            baseState.reset();
            return result;
        })
        .withSinglePass((src, offset, length) -> {
            assertInitialized();
            final byte[] result = new byte[HASH_SIZE];
            fastHmac(baseState.normalKey, src, offset, length, result);
            baseState.reset();
            return result;
        });
    }

    @SuppressWarnings("unchecked")
    @Override
    public Object clone() throws CloneNotSupportedException {
        TemplateHmacSpi clonedObject = (TemplateHmacSpi) super.clone();
        clonedObject.oneByteArray = null; // This is lazily created if needed

        clonedObject.baseState = clonedObject.baseState.copy(); // It's easier not to boostrap from clone in this case
        clonedObject.buffer = (InputBuffer<byte[], Void>) clonedObject.buffer.clone();
        clonedObject.setLambdas(clonedObject.buffer);

        return clonedObject;
    }

    private void assertInitialized() {
        if (!baseState.initialized) {
            throw new IllegalStateException("Mac not initialized");
        }
    }

    @Override
    protected byte[] engineDoFinal() {
        try {
            return buffer.doFinal();
        } finally {
            engineReset();
        }
    }

    @Override
    protected int engineGetMacLength() {
        return HASH_SIZE;
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("Params must be null");
        }
        if (!(key instanceof SecretKey)) {
            throw new InvalidKeyException("Hmac uses expects a SecretKey");
        }
        // Algorithm is explicitly NOT checked for compatibility with existing
        // JCE implementations such as SUN and BouncyCastle
        if (!"RAW".equalsIgnoreCase(key.getFormat())) {
            throw new InvalidKeyException("Key must support RAW encoding");
        }
        byte[] rawKey = key.getEncoded();
        if (rawKey == null) {
            throw new InvalidKeyException("Key encoding must not be null");
        }
        baseState.setKey(rawKey);
        engineReset();
    }

    @Override
    protected void engineReset() {
        buffer.reset();
    }

    @Override
    protected void engineUpdate(byte val) {
        buffer.update(val);
    }

    @Override
    protected void engineUpdate(byte[] src, int offset, int length) {
        buffer.update(src, offset, length);
    }

    @Override
    protected void engineUpdate(ByteBuffer input) {
        buffer.update(input);
    }
}
