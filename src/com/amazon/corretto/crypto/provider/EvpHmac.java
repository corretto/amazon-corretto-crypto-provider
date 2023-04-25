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
   * Calls {@code HMAC_Update} with {@code input}, possibly calling {@code HMAC_Init_ex} first (if
   * {@code evpMd} is any value except {@link #DO_NOT_INIT}). This method should only be used via
   * {@link #synchronizedUpdateCtxArray(byte[], byte[], long, byte[], int, int)}.
   *
   * @param ctx opaque array containing native context
   */
  private static native void updateCtxArray(
      byte[] ctx, byte[] key, long evpMd, byte[] input, int offset, int length);
  /**
   * @see {@link #updateCtxArray(byte[], byte[], long, byte[], int, int)}
   */
  private static void synchronizedUpdateCtxArray(
      byte[] ctx, byte[] key, long evpMd, byte[] input, int offset, int length) {
    synchronized (ctx) {
      updateCtxArray(ctx, key, evpMd, input, offset, length);
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
   * int, int, byte[])}.
   *
   * @param ctx opaque array containing native context
   */
  private static native void fastHmac(
      byte[] ctx, byte[] key, long evpMd, byte[] input, int offset, int length, byte[] result);
  /**
   * @see {@link #fastHmac(byte[], byte[], long, byte[], int, int, byte[])}
   */
  private static void synchronizedFastHmac(
      byte[] ctx, byte[] key, long evpMd, byte[] input, int offset, int length, byte[] result) {
    synchronized (ctx) {
      fastHmac(ctx, key, evpMd, input, offset, length, result);
    }
  }

  private static final int CONTEXT_SIZE = getContextSize();

  // These must be explicitly cloned
  private HmacState state;
  private InputBuffer<byte[], Void, RuntimeException> buffer;

  EvpHmac(long evpMd, int digestLength) {
    if (evpMd == DO_NOT_INIT || evpMd == DO_NOT_REKEY) {
      throw new AssertionError(
          "Unexpected value for evpMd conflicting with reserved negative value: " + evpMd);
    }
    this.state = new HmacState(evpMd, digestLength);
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
              synchronizedUpdateCtxArray(state.context, rawKey, evpMd, src, offset, length);
              state.needsRekey = false;
              return null;
            })
        .withUpdater(
            (ignored, src, offset, length) -> {
              assertInitialized();
              synchronizedUpdateCtxArray(state.context, null, DO_NOT_INIT, src, offset, length);
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
              synchronizedFastHmac(state.context, rawKey, evpMd, src, offset, length, result);
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
    private final int digestLength;
    private byte[] context = new byte[CONTEXT_SIZE];
    private byte[] encoded_key;
    boolean needsRekey = true;

    private HmacState(long evpMd, int digestLength) {
      this.evpMd = evpMd;
      this.digestLength = digestLength;
    }

    private void setKey(SecretKey key) throws InvalidKeyException {
      if (Objects.equals(this.key, key)) {
        return;
      }
      // Check new key for usability
      if (!"RAW".equalsIgnoreCase(key.getFormat())) {
        throw new InvalidKeyException("Key must support RAW encoding");
      }
      byte[] encoded = key.getEncoded();
      if (encoded == null) {
        throw new InvalidKeyException("Key encoding must not be null");
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

  static class MD5 extends EvpHmac {
    private static final long evpMd = Utils.getEvpMdFromName("md5");
    private static final int digestLength = Utils.getDigestLength(evpMd);
    static final SelfTestSuite.SelfTest SELF_TEST =
        new SelfTestSuite.SelfTest("HmacMD5", MD5::runSelfTest);

    public MD5() {
      super(evpMd, digestLength);
    }

    public static SelfTestResult runSelfTest() {
      return EvpHmac.runSelfTest("HmacMD5", MD5.class);
    }
  }

  static class SHA1 extends EvpHmac {
    private static final long evpMd = Utils.getEvpMdFromName("sha1");
    private static final int digestLength = Utils.getDigestLength(evpMd);
    static final SelfTestSuite.SelfTest SELF_TEST =
        new SelfTestSuite.SelfTest("HmacSHA1", SHA1::runSelfTest);

    public SHA1() {
      super(evpMd, digestLength);
    }

    public static SelfTestResult runSelfTest() {
      return EvpHmac.runSelfTest("HmacSHA1", SHA1.class);
    }
  }

  static class SHA256 extends EvpHmac {
    private static final long evpMd = Utils.getEvpMdFromName("sha256");
    private static final int digestLength = Utils.getDigestLength(evpMd);
    static final SelfTestSuite.SelfTest SELF_TEST =
        new SelfTestSuite.SelfTest("HmacSHA256", SHA256::runSelfTest);

    public SHA256() {
      super(evpMd, digestLength);
    }

    public static SelfTestResult runSelfTest() {
      return EvpHmac.runSelfTest("HmacSHA256", SHA256.class);
    }
  }

  static class SHA384 extends EvpHmac {
    private static final long evpMd = Utils.getEvpMdFromName("sha384");
    private static final int digestLength = Utils.getDigestLength(evpMd);
    static final SelfTestSuite.SelfTest SELF_TEST =
        new SelfTestSuite.SelfTest("HmacSHA384", SHA384::runSelfTest);

    public SHA384() {
      super(evpMd, digestLength);
    }

    public static SelfTestResult runSelfTest() {
      return EvpHmac.runSelfTest("HmacSHA384", SHA384.class);
    }
  }

  static class SHA512 extends EvpHmac {
    private static final long evpMd = Utils.getEvpMdFromName("sha512");
    private static final int digestLength = Utils.getDigestLength(evpMd);
    static final SelfTestSuite.SelfTest SELF_TEST =
        new SelfTestSuite.SelfTest("HmacSHA512", SHA512::runSelfTest);

    public SHA512() {
      super(evpMd, digestLength);
    }

    public static SelfTestResult runSelfTest() {
      return EvpHmac.runSelfTest("HmacSHA512", SHA512.class);
    }
  }
}
