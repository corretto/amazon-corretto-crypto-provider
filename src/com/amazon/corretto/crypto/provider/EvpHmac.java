// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import static java.util.logging.Logger.getLogger;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Scanner;
import javax.crypto.Mac;
import javax.crypto.MacSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

class EvpHmac extends MacSpi implements Cloneable {
  static final String HMAC_PREFIX = "Hmac";
  static final String WITH_PRECOMPUTED_KEY = "WithPrecomputedKey";

  static final String HMAC_SHA512_WITH_PRECOMPUTED_KEY =
      HMAC_PREFIX + "SHA512" + WITH_PRECOMPUTED_KEY;
  static final String HMAC_SHA384_WITH_PRECOMPUTED_KEY =
      HMAC_PREFIX + "SHA384" + WITH_PRECOMPUTED_KEY;
  static final String HMAC_SHA256_WITH_PRECOMPUTED_KEY =
      HMAC_PREFIX + "SHA256" + WITH_PRECOMPUTED_KEY;
  static final String HMAC_SHA1_WITH_PRECOMPUTED_KEY = HMAC_PREFIX + "SHA1" + WITH_PRECOMPUTED_KEY;
  static final String HMAC_MD5_WITH_PRECOMPUTED_KEY = HMAC_PREFIX + "MD5" + WITH_PRECOMPUTED_KEY;

  /** When passed to {@code evpMd} indicates that the native code should not call HMAC_Init_ex. */
  private static long DO_NOT_INIT = -1;

  /**
   * When passed to {@code evpMd} indicates that while {@code HMAC_Init_ex} must be called, it
   * should be called with NULL for both the key and evpMd parameters.
   */
  private static long DO_NOT_REKEY = -2;

  /** Returns the size of the array needed to hold the entire HMAC context. */
  private static native int getContextSize();

  /**
   * Returns the length of the precomputed key for the HMAC for the hash function with name
   * digestName
   *
   * @param digestName name of the digest (md5,sha1,sha256,sha384,sha512)
   * @return the length of the precomputed key, in bytes
   */
  static native int getPrecomputedKeyLength(String digestName);

  /**
   * Calls {@code HMAC_Update} with {@code input}, possibly calling {@code HMAC_Init_ex} or {@code
   * HMAC_Init_from_precomputed_key} first (if {@code evpMd} is any value except {@link
   * #DO_NOT_INIT}). This method should only be used via {@link #synchronizedUpdateCtxArray(byte[],
   * byte[], long, byte[], int, int, boolean)}.
   *
   * @param ctx opaque array containing native context
   */
  private static native void updateCtxArray(
      byte[] ctx,
      byte[] key,
      long evpMd,
      byte[] input,
      int offset,
      int length,
      boolean usePrecomputedKey);

  /**
   * @see {@link #updateCtxArray(byte[], byte[], long, byte[], int, int, boolean)}
   */
  private static void synchronizedUpdateCtxArray(
      byte[] ctx,
      byte[] key,
      long evpMd,
      byte[] input,
      int offset,
      int length,
      boolean usePrecomputedKey) {
    synchronized (ctx) {
      updateCtxArray(ctx, key, evpMd, input, offset, length, usePrecomputedKey);
    }
  }

  /**
   * Calls {@code HMAC_Final}, and places the result in {@code result}. This method should only be
   * called via {@link #synchronizedDoFinal(byte[], byte[])}
   *
   * @param ctx opaque array containing native context
   * @param result
   */
  private static native void doFinal(byte[] ctx, byte[] result);

  /**
   * @see {@link #doFinal(byte[], byte[])}
   */
  private static void synchronizedDoFinal(byte[] ctx, byte[] result) {
    synchronized (ctx) {
      doFinal(ctx, result);
    }
  }

  /**
   * Calls {@code HMAC_Init_ex}, {@code HMAC_Update}, and {@code HMAC_Final} with {@code input}.
   * This method should only be used via {@link #synchronizedFastHmac(byte[], byte[], long, byte[],
   * int, int, byte[], boolean)}.
   *
   * @param ctx opaque array containing native context
   */
  private static native void fastHmac(
      byte[] ctx,
      byte[] key,
      long evpMd,
      byte[] input,
      int offset,
      int length,
      byte[] result,
      boolean usePrecomputedKey);

  /**
   * @see {@link #fastHmac(byte[], byte[], long, byte[], int, int, byte[], boolean)}
   */
  private static void synchronizedFastHmac(
      byte[] ctx,
      byte[] key,
      long evpMd,
      byte[] input,
      int offset,
      int length,
      byte[] result,
      boolean usePrecomputedKey) {
    synchronized (ctx) {
      fastHmac(ctx, key, evpMd, input, offset, length, result, usePrecomputedKey);
    }
  }

  private static final int CONTEXT_SIZE = getContextSize();

  // These must be explicitly cloned
  private HmacState state;
  private InputBuffer<byte[], Void, RuntimeException> buffer;

  private static final String WITH_PRECOMPUTE_KEY = "WithPrecomputedKey";

  /**
   * @param digestName is the name of the digest in lowercase (e.g., "sha256", "md5")
   * @param baseAlgorithm the base name of the algorithm without "WithPrecomputedKey" (e.g.,
   *     "HmacMd5")
   * @param usePrecomputedKey true is using precomputed keys instead of normal keys
   */
  EvpHmac(String digestName, final String baseAlgorithm, final boolean usePrecomputedKey) {
    final long evpMd = Utils.getEvpMdFromName(digestName);
    final int digestLength = Utils.getDigestLength(evpMd);
    int precomputedKeyLength = 0;
    if (usePrecomputedKey) {
      precomputedKeyLength = getPrecomputedKeyLength(digestName);
    }

    if (evpMd == DO_NOT_INIT || evpMd == DO_NOT_REKEY) {
      throw new AssertionError(
          "Unexpected value for evpMd conflicting with reserved negative value: " + evpMd);
    }
    String algorithm = baseAlgorithm;
    if (usePrecomputedKey) {
      algorithm += WITH_PRECOMPUTE_KEY;
    }
    this.state =
        new HmacState(evpMd, digestLength, algorithm, usePrecomputedKey, precomputedKeyLength);
    this.buffer = new InputBuffer<byte[], Void, RuntimeException>(1024);
    configureLambdas();
  }

  private void configureLambdas() {
    buffer
        .withInitialUpdater(
            (src, offset, length) -> {
              assertInitialized();
              byte[] rawKey = state.encoded_key;
              long evpMd = DO_NOT_REKEY;
              if (state.needsRekey) {
                evpMd = state.evpMd;
              }
              synchronizedUpdateCtxArray(
                  state.context, rawKey, evpMd, src, offset, length, state.usePrecomputedKey);
              state.needsRekey = false;
              return null;
            })
        .withUpdater(
            (ignored, src, offset, length) -> {
              assertInitialized();
              synchronizedUpdateCtxArray(
                  state.context, null, DO_NOT_INIT, src, offset, length, state.usePrecomputedKey);
            })
        .withDoFinal(
            (ignored) -> {
              assertInitialized();
              final byte[] result = new byte[state.digestLength];
              synchronizedDoFinal(state.context, result);
              return result;
            })
        .withSinglePass(
            (src, offset, length) -> {
              assertInitialized();
              final byte[] result = new byte[state.digestLength];
              byte[] rawKey = state.encoded_key;
              long evpMd = DO_NOT_REKEY;
              if (state.needsRekey) {
                evpMd = state.evpMd;
              }
              synchronizedFastHmac(
                  state.context,
                  rawKey,
                  evpMd,
                  src,
                  offset,
                  length,
                  result,
                  state.usePrecomputedKey);
              state.needsRekey = false;
              return result;
            });
  }

  @Override
  protected int engineGetMacLength() {
    return state.digestLength;
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
    state.setKey((SecretKey) key);
    engineReset();
  }

  @Override
  protected void engineUpdate(byte input) {
    buffer.update(input);
  }

  @Override
  protected void engineUpdate(byte[] input, int offset, int len) {
    buffer.update(input, offset, len);
  }

  @Override
  protected byte[] engineDoFinal() {
    return buffer.doFinal();
  }

  @Override
  protected void engineReset() {
    buffer.reset();
  }

  private void assertInitialized() {
    if (state.key == null) {
      throw new IllegalStateException("Mac not initialized");
    }
  }

  @Override
  public EvpHmac clone() throws CloneNotSupportedException {
    EvpHmac cloned = (EvpHmac) super.clone();
    cloned.state = cloned.state.clone();
    cloned.buffer = cloned.buffer.clone();
    cloned.configureLambdas();
    return cloned;
  }

  private static final class HmacState implements Cloneable {
    private SecretKey key;
    private final long evpMd;

    /**
     * Name of the algorithm used to create this instance. This is used to ensure that the key is
     * appropriate for the algorithm, when using precomputed keys.
     */
    private final String algorithm;

    private final int digestLength;
    private byte[] context = new byte[CONTEXT_SIZE];
    private byte[] encoded_key;

    /**
     * True if precomputed keys are used instead of raw HMAC keys, that is for algorithms
     * `HmacXXXWithPrecomputedKey`.
     */
    private final boolean usePrecomputedKey;

    private final int precomputedKeyLength;

    boolean needsRekey = true;

    /**
     * @param evpMd the evpMd corresponding to the digest used
     * @param digestLength the length of the digest in bytes
     * @param algorithm the full name algorithm (e.g., "HmacMD5" or "HmacMD5WithPrecomputedKey")
     * @param usePrecomputedKey false = normal HMAC, true = uses precomputed keys
     * @param precomputedKeyLength length of precomputed keys in bytes (can be 0 if
     *     usePrecomputedKey = false)
     */
    private HmacState(
        final long evpMd,
        final int digestLength,
        final String algorithm,
        final boolean usePrecomputedKey,
        final int precomputedKeyLength) {
      this.evpMd = evpMd;
      this.digestLength = digestLength;
      this.algorithm = Objects.requireNonNull(algorithm);
      this.usePrecomputedKey = usePrecomputedKey;
      this.precomputedKeyLength = precomputedKeyLength;
    }

    private void setKey(SecretKey key) throws InvalidKeyException {
      if (Objects.equals(this.key, key)) {
        return;
      }
      // Check new key for usability
      if (!"RAW".equalsIgnoreCase(key.getFormat())) {
        throw new InvalidKeyException("Key must support RAW encoding");
      }
      if (usePrecomputedKey && !algorithm.equalsIgnoreCase(key.getAlgorithm())) {
        throw new InvalidKeyException(
            "Key must be for algorithm \"" + algorithm + "\" when using precomputed keys");
      }

      byte[] encoded = key.getEncoded();
      if (encoded == null) {
        throw new InvalidKeyException("Key encoding must not be null");
      }
      if (usePrecomputedKey && encoded.length != precomputedKeyLength) {
        throw new InvalidKeyException(
            "Key must be of length \"" + precomputedKeyLength + "\" when using precomputed keys");
      }
      this.encoded_key = encoded;
      this.key = key;
      this.needsRekey = true;
    }

    @Override
    public HmacState clone() {
      try {
        HmacState cloned = (HmacState) super.clone();
        cloned.context = cloned.context.clone();
        return cloned;
      } catch (final CloneNotSupportedException ex) {
        throw new AssertionError(ex);
      }
    }
  }

  @SuppressWarnings("serial")
  private static class TestMacProvider extends Provider {
    private final String macName;
    private final Class<? extends MacSpi> spi;

    // The superconstructor taking a double version is deprecated in java 9.
    // However, the replacement for it is
    // unavailable in java 8, so to build on both with warnings on our only choice
    // is suppress deprecation warnings.
    @SuppressWarnings({"deprecation"})
    protected TestMacProvider(String macName, Class<? extends MacSpi> spi) {
      super("test provider", 0, "internal self-test provider for " + macName);
      this.macName = macName;
      this.spi = spi;
    }

    @Override
    public synchronized Service getService(final String type, final String algorithm) {
      if (type.equals("Mac") && algorithm.equals(macName)) {
        return new Service(
            this, type, algorithm, spi.getName(), Collections.emptyList(), Collections.emptyMap()) {
          @Override
          public Object newInstance(final Object constructorParameter) {
            try {
              return spi.getConstructor().newInstance();
            } catch (final Exception ex) {
              throw new AssertionError(ex);
            }
          }
        };
      } else {
        return super.getService(type, algorithm);
      }
    }
  }

  private static SelfTestResult runSelfTest(String macName, Class<? extends MacSpi> spi) {
    Provider p = new TestMacProvider(macName, spi);

    int tests = 0;
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

    try (final Scanner in =
        new Scanner(Loader.getTestData("hmac.txt"), StandardCharsets.US_ASCII.name())) {
      final Mac testMac = Mac.getInstance(macName, p);
      while (in.hasNext()) {
        tests++;
        final String type = in.next();
        SecretKey key = new SecretKeySpec(Utils.decodeHex(in.next()), macName);
        byte[] message = Utils.decodeHex(in.next());
        String[] expecteds = in.nextLine().trim().split("\\s+");
        if (type.equals(hashCategory.get(macName))) {
          Utils.testMac(
              testMac, key, message, Utils.decodeHex(expecteds[hashLocation.get(macName)]));
        }
      }
      return new SelfTestResult(SelfTestStatus.PASSED);
    } catch (Throwable ex) {
      getLogger("AmazonCorrettoCryptoProvider").severe(macName + " failed self-test " + tests);
      return new SelfTestResult(ex);
    }
  }

  private static class MD5Base extends EvpHmac {
    protected static final String digestName = "md5";
    protected static final String baseAlgorithm = "HmacMD5";

    private MD5Base(boolean usePrecomputedKey) {
      super(digestName, baseAlgorithm, usePrecomputedKey);
    }
  }

  static class MD5 extends MD5Base {
    static final SelfTestSuite.SelfTest SELF_TEST =
        new SelfTestSuite.SelfTest(baseAlgorithm, MD5::runSelfTest);

    public MD5() {
      super(false);
    }

    public static SelfTestResult runSelfTest() {
      return EvpHmac.runSelfTest(baseAlgorithm, MD5.class);
    }
  }

  static class MD5WithPrecomputedKey extends MD5Base {
    public MD5WithPrecomputedKey() {
      super(true);
    }
  }

  private static class SHA1Base extends EvpHmac {
    protected static final String digestName = "sha1";
    protected static final String baseAlgorithm = "HmacSHA1";

    private SHA1Base(boolean usePrecomputedKey) {
      super(digestName, baseAlgorithm, usePrecomputedKey);
    }
  }

  static class SHA1 extends SHA1Base {
    static final SelfTestSuite.SelfTest SELF_TEST =
        new SelfTestSuite.SelfTest(baseAlgorithm, SHA1::runSelfTest);

    public SHA1() {
      super(false);
    }

    public static SelfTestResult runSelfTest() {
      return EvpHmac.runSelfTest(baseAlgorithm, SHA1.class);
    }
  }

  static class SHA1WithPrecomputedKey extends SHA1Base {
    public SHA1WithPrecomputedKey() {
      super(true);
    }
  }

  private static class SHA256Base extends EvpHmac {
    protected static final String digestName = "sha256";
    protected static final String baseAlgorithm = "HmacSHA256";

    private SHA256Base(boolean usePrecomputedKey) {
      super(digestName, baseAlgorithm, usePrecomputedKey);
    }
  }

  static class SHA256 extends SHA256Base {
    static final SelfTestSuite.SelfTest SELF_TEST =
        new SelfTestSuite.SelfTest(baseAlgorithm, SHA256::runSelfTest);

    public SHA256() {
      super(false);
    }

    public static SelfTestResult runSelfTest() {
      return EvpHmac.runSelfTest(baseAlgorithm, SHA256.class);
    }
  }

  static class SHA256WithPrecomputedKey extends SHA256Base {
    public SHA256WithPrecomputedKey() {
      super(true);
    }
  }

  private static class SHA384Base extends EvpHmac {
    protected static final String digestName = "sha384";
    protected static final String baseAlgorithm = "HmacSHA384";

    private SHA384Base(boolean usePrecomputedKey) {
      super(digestName, baseAlgorithm, usePrecomputedKey);
    }
  }

  static class SHA384 extends SHA384Base {
    static final SelfTestSuite.SelfTest SELF_TEST =
        new SelfTestSuite.SelfTest(baseAlgorithm, SHA384::runSelfTest);

    public SHA384() {
      super(false);
    }

    public static SelfTestResult runSelfTest() {
      return EvpHmac.runSelfTest(baseAlgorithm, SHA384.class);
    }
  }

  static class SHA384WithPrecomputedKey extends SHA384Base {
    public SHA384WithPrecomputedKey() {
      super(true);
    }
  }

  private static class SHA512Base extends EvpHmac {
    protected static final String digestName = "sha512";
    protected static final String baseAlgorithm = "HmacSHA512";

    private SHA512Base(boolean usePrecomputedKey) {
      super(digestName, baseAlgorithm, usePrecomputedKey);
    }
  }

  static class SHA512 extends SHA512Base {
    static final SelfTestSuite.SelfTest SELF_TEST =
        new SelfTestSuite.SelfTest(baseAlgorithm, SHA512::runSelfTest);

    public SHA512() {
      super(false);
    }

    public static SelfTestResult runSelfTest() {
      return EvpHmac.runSelfTest(baseAlgorithm, SHA512.class);
    }
  }

  static class SHA512WithPrecomputedKey extends SHA512Base {
    public SHA512WithPrecomputedKey() {
      super(true);
    }
  }
}
