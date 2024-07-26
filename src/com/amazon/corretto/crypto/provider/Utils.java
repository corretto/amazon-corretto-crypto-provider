// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.nio.ByteBuffer;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/** Miscellaneous utility methods. */
final class Utils {
  static final int SHA1_CODE = 1;
  static final int SHA256_CODE = 2;
  static final int SHA384_CODE = 3;
  static final int SHA512_CODE = 4;
  private static final String PROPERTY_NATIVE_CONTEXT_RELEASE_STRATEGY =
      "nativeContextReleaseStrategy";

  private Utils() {
    // Prevent instantiation
  }

  static final byte[] EMPTY_ARRAY = new byte[0];
  private static final Logger LOG = Logger.getLogger("AmazonCorrettoCryptoProvider");

  private static final Map<String, Long> digestPtrByName = new ConcurrentHashMap<>();
  private static final Map<Long, Integer> digestLengthByPtr = new ConcurrentHashMap<>();

  /**
   * Returns the difference between the native pointers of a and b. That is, if overlap > 0, then
   * a.get(overlap) == b.get(0), and if overlap < 0, then b.get(-overlap) == a.get(0).
   *
   * <p>If the buffers do not overlap, or if one of the arguments is not a direct byte buffer,
   * returns a value greater than Integer.MAX_VALUE.
   *
   * @param a
   * @param b
   * @return
   */
  static native long getNativeBufferOffset(ByteBuffer a, ByteBuffer b);

  /**
   * Returns the value of the EVP_MD* object corresponding with the named digest. Corresponds to a
   * call to @{code EVP_get_digestbyname}.
   */
  static native long getEvpMdFromName(String digestName);
  /** Returns the output length for a digest in bytes specified by {@code evpMd}. */
  static native int getDigestLength(long evpMd);

  static int getDigestLength(final String digestName) {
    return getDigestLength(getEvpMdFromName(digestName));
  }

  static String jceDigestNameToAwsLcName(final String jceName) {
    if (jceName == null) {
      return null;
    }
    // e.g. "SHA-512/256" => "SHA512-256"
    return jceName.replace("-", "").replace("/", "-").toUpperCase();
  }

  /**
   * Converts a hash name (according to JCE standards) to an {@code long} containing the value of
   * the native {@code EVP_MD*} pointer. If {@code digestName == null} then this will return {@code
   * 0}. Otherwise this is guaranteed to return a non-zero value as it will throw {@link
   * IllegalArgumentException} if libcrypto cannot translate the name into a known {@code EVP_MD*}
   * pointer.
   */
  static long getMdPtr(final String digestName) {
    if (digestName == null) {
      return 0;
    }
    final String name = jceDigestNameToAwsLcName(digestName);

    if (!name.startsWith("SHA")) {
      throw new IllegalArgumentException("Unsupported digest algorithm: " + digestName);
    }
    final long ptr = digestPtrByName.computeIfAbsent(name, Utils::getEvpMdFromName);
    if (ptr == 0) {
      throw new IllegalArgumentException("Unsupported digest algorith: " + digestName);
    }
    return ptr;
  }

  static int getMdLen(final long mdPtr) {
    return digestLengthByPtr.computeIfAbsent(mdPtr, Utils::getDigestLength);
  }

  /**
   * Returns false if there is no chance of the output buffer overwriting unread input; true if we
   * determine that unsafe overwriting input is possible.
   *
   * <p>Overlap is determined based on buffer position and limit.
   */
  static boolean outputClobbersInput(ByteBuffer inputBuffer, ByteBuffer outputBuffer) {
    boolean inputIsDirect = inputBuffer.isDirect();
    boolean outputIsDirect = outputBuffer.isDirect();
    boolean inputHasArray = inputBuffer.hasArray();
    boolean outputHasArray = outputBuffer.hasArray();

    if ((inputIsDirect || outputIsDirect) && (inputIsDirect != outputIsDirect)) {
      // One is direct and the other isn't; there can be no overlap
      return false;
    }

    if (inputIsDirect && outputIsDirect) {
      // By slicing the buffers, we can avoid having to think about the native pointer and
      // position(); the position will simply be added into the native pointer.

      // This will also allow getNativeBufferOffset to fully determine whether the buffers overlap
      // in native code, by factoring the limit() into the buffer capacity.
      return getNativeBufferOffset(inputBuffer.slice(), outputBuffer.slice()) <= Integer.MAX_VALUE;
    }

    // At this point we'll need to check array() and arrayOffset(), but to do this we need both to
    // hasArray().
    if (!(inputHasArray && outputHasArray)) {
      // One doesn't hasArray, so we're prevented from checking for overlap. Return true to assume
      // overlap.
      return true;
    }

    // We've got two arrays, check if there's a chance for clobbering.
    int inputOffset = inputBuffer.arrayOffset() + inputBuffer.position();
    int outputOffset = outputBuffer.arrayOffset() + outputBuffer.position();
    return outputClobbersInput(
        inputBuffer.array(),
        inputOffset,
        inputBuffer.remaining(),
        outputBuffer.array(),
        outputOffset);
  }

  /**
   * @return True if the output will overwrite portions of the input before it gets processed.
   */
  static boolean outputClobbersInput(
      byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset) {
    // If these are different arrays they don't overlap
    if (input != output) {
      return false;
    }

    // We can tolerate the output overlapping the input as long as the output starts at the same
    // point or earlier. This is because the block cipher implementation operates block by block and
    // is built to overwrite the input block in-place. If the output offset leads the input offset,
    // the output of the current block will overwrite the input of the next block and it will break
    // the operation.
    if (outputOffset <= inputOffset) {
      return false;
    }

    // If the output starts after the input ends, then we're not clobbering anything.
    int inputEnd = inputOffset + inputLength;
    if (outputOffset >= inputEnd) {
      return false;
    }

    return true;
  }

  static byte[] encodeForWrapping(final AmazonCorrettoCryptoProvider provider, final Key key)
      throws InvalidKeyException {
    try {
      final byte[] encoded;
      if (key instanceof SecretKey) {
        encoded = key.getEncoded();
      } else if (key instanceof PublicKey) {
        final KeyFactory factory = getKeyFactory(provider, key.getAlgorithm());
        encoded = factory.getKeySpec(key, X509EncodedKeySpec.class).getEncoded();
      } else if (key instanceof PrivateKey) {
        final KeyFactory factory = getKeyFactory(provider, key.getAlgorithm());
        encoded = factory.getKeySpec(key, PKCS8EncodedKeySpec.class).getEncoded();
      } else {
        throw new InvalidKeyException("Key does not implement SecretKey, PublicKey, or PrivateKey");
      }
      if (encoded == null || encoded.length == 0) {
        throw new InvalidKeyException("Could not obtain encoded key");
      }
      return encoded;
    } catch (final InvalidKeySpecException | NoSuchAlgorithmException ex) {
      throw new InvalidKeyException("Wrapping failed", ex);
    }
  }

  static byte[] encodeForWrapping(final Key key) throws InvalidKeyException {
    return encodeForWrapping(AmazonCorrettoCryptoProvider.INSTANCE, key);
  }

  static Key buildUnwrappedKey(
      final AmazonCorrettoCryptoProvider provider,
      final byte[] rawKey,
      final String algorithm,
      final int keyType)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    switch (keyType) {
      case Cipher.SECRET_KEY:
        return buildUnwrappedSecretKey(rawKey, algorithm);
      case Cipher.PUBLIC_KEY:
        return buildUnwrappedPublicKey(provider, rawKey, algorithm);
      case Cipher.PRIVATE_KEY:
        return buildUnwrappedPrivateKey(provider, rawKey, algorithm);
      default:
        throw new IllegalArgumentException("Unexpected key type: " + keyType);
    }
  }

  static Key buildUnwrappedKey(final byte[] rawKey, final String algorithm, final int keyType)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    return buildUnwrappedKey(AmazonCorrettoCryptoProvider.INSTANCE, rawKey, algorithm, keyType);
  }

  static SecretKey buildUnwrappedSecretKey(final byte[] rawKey, final String algorithm) {
    return new SecretKeySpec(rawKey, algorithm);
  }

  static PublicKey buildUnwrappedPublicKey(
      final AmazonCorrettoCryptoProvider provider, final byte[] rawKey, final String algorithm)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    final KeyFactory kf = getKeyFactory(provider, algorithm);
    return kf.generatePublic(new X509EncodedKeySpec(rawKey));
  }

  static PrivateKey buildUnwrappedPrivateKey(
      final AmazonCorrettoCryptoProvider provider, final byte[] rawKey, final String algorithm)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    final KeyFactory kf = getKeyFactory(provider, algorithm);
    return kf.generatePrivate(new PKCS8EncodedKeySpec(rawKey));
  }

  static byte[] xor(final byte[] a, final byte[] b) {
    if (a.length != b.length) {
      throw new IllegalArgumentException("arrays must be the same length");
    }
    final byte[] result = new byte[a.length];
    for (int x = 0; x < a.length; x++) {
      result[x] = (byte) (a[x] ^ b[x]);
    }
    return result;
  }

  static byte[] decodeHex(String hex) {
    if (hex.length() % 2 != 0) {
      throw new IllegalArgumentException("Input length must be even");
    }
    byte[] result = new byte[hex.length() / 2];
    for (int x = 0; x < hex.length() / 2; x++) {
      result[x] = (byte) Integer.parseInt(hex.substring(2 * x, 2 * x + 2), 16);
    }
    return result;
  }

  private static void assertArrayEquals(String message, byte[] expected, byte[] actual) {
    if (!Arrays.equals(expected, actual)) {
      throw new AssertionError("Arrays do not match: " + message);
    }
  }

  public static void testMac(Mac mac, SecretKey key, byte[] message, byte[] expected)
      throws GeneralSecurityException {
    mac.init(key);
    final int[] lengths = new int[] {1, 3, 4, 7, 8, 16, 32, 48, 64, 128, 256};
    final String alg = mac.getAlgorithm();
    assertArrayEquals(alg, expected, mac.doFinal(message));
    for (int x = 0; x < message.length; x++) {
      mac.update(message[x]);
    }
    assertArrayEquals(alg + "-Byte", expected, mac.doFinal());
    for (final int length : lengths) {
      for (int x = 0; x < message.length; x += length) {
        final int len = x + length > message.length ? message.length - x : length;
        mac.update(message, x, len);
      }
      assertArrayEquals(alg + "-" + length, expected, mac.doFinal());
    }

    // Byte buffer wrapping
    mac.update(ByteBuffer.wrap(message));
    assertArrayEquals(alg + "-ByteBuffer-Wrap", expected, mac.doFinal());

    for (final int length : lengths) {
      for (int x = 0; x < message.length; x += length) {
        final int len = x + length > message.length ? message.length - x : length;
        mac.update(ByteBuffer.wrap(message, x, len));
      }
      assertArrayEquals(alg + "-ByteBuffer-Wrap-" + length, expected, mac.doFinal());
    }

    // Byte buffer wrapping, read-only
    mac.update(ByteBuffer.wrap(message).asReadOnlyBuffer());
    assertArrayEquals(alg + "-ByteBuffer-Wrap-RO", expected, mac.doFinal());

    for (final int length : lengths) {
      for (int x = 0; x < message.length; x += length) {
        final int len = x + length > message.length ? message.length - x : length;
        mac.update(ByteBuffer.wrap(message, x, len).asReadOnlyBuffer());
      }
      assertArrayEquals(alg + "-ByteBuffer-Wrap-RO-" + length, expected, mac.doFinal());
    }

    // Byte buffer non-direct
    ByteBuffer bbuff = ByteBuffer.allocate(message.length);
    bbuff.put(message);
    bbuff.flip();
    mac.update(bbuff);
    assertArrayEquals(alg + "-ByteBuffer-NonDirect", expected, mac.doFinal());

    for (final int length : lengths) {
      bbuff = ByteBuffer.allocate(length);
      for (int x = 0; x < message.length; x += length) {
        final int len = x + length > message.length ? message.length - x : length;
        bbuff.clear();
        bbuff.put(message, x, len);
        bbuff.flip();
        mac.update(bbuff);
      }
      assertArrayEquals(alg + "-ByteBuffer-NonDirect-" + length, expected, mac.doFinal());
    }

    // Byte buffer direct
    bbuff = ByteBuffer.allocateDirect(message.length);
    bbuff.put(message);
    bbuff.flip();
    mac.update(bbuff);
    assertArrayEquals(alg + "-ByteBuffer-Direct", expected, mac.doFinal());

    for (final int length : lengths) {
      bbuff = ByteBuffer.allocateDirect(length);
      for (int x = 0; x < message.length; x += length) {
        final int len = x + length > message.length ? message.length - x : length;
        bbuff.clear();
        bbuff.put(message, x, len);
        bbuff.flip();
        mac.update(bbuff);
      }
      assertArrayEquals(alg + "-ByteBuffer-Direct-" + length, expected, mac.doFinal());
    }

    // Byte buffer direct, read-only
    bbuff = ByteBuffer.allocateDirect(message.length);
    bbuff.put(message);
    bbuff.flip();
    mac.update(bbuff.asReadOnlyBuffer());
    assertArrayEquals(alg + "-ByteBuffer-Direct", expected, mac.doFinal());

    for (final int length : lengths) {
      bbuff = ByteBuffer.allocateDirect(length);
      for (int x = 0; x < message.length; x += length) {
        final int len = x + length > message.length ? message.length - x : length;
        bbuff.clear();
        bbuff.put(message, x, len);
        bbuff.flip();
        mac.update(bbuff.asReadOnlyBuffer());
      }
      assertArrayEquals(alg + "-ByteBuffer-Direct-" + length, expected, mac.doFinal());
    }
  }

  public static void testDigest(MessageDigest md, byte[] message, byte[] expected) {
    final int[] lengths = new int[] {1, 3, 4, 7, 8, 16, 32, 48, 64, 128, 256};
    final String alg = md.getAlgorithm();
    assertArrayEquals(alg, expected, md.digest(message));
    for (int x = 0; x < message.length; x++) {
      md.update(message[x]);
    }
    assertArrayEquals(alg + "-Byte", expected, md.digest());
    for (final int length : lengths) {
      for (int x = 0; x < message.length; x += length) {
        final int len = x + length > message.length ? message.length - x : length;
        md.update(message, x, len);
      }
      assertArrayEquals(alg + "-" + length, expected, md.digest());
    }

    // Byte buffer wrapping
    md.update(ByteBuffer.wrap(message));
    assertArrayEquals(alg + "-ByteBuffer-Wrap", expected, md.digest());

    for (final int length : lengths) {
      for (int x = 0; x < message.length; x += length) {
        final int len = x + length > message.length ? message.length - x : length;
        md.update(ByteBuffer.wrap(message, x, len));
      }
      assertArrayEquals(alg + "-ByteBuffer-Wrap-" + length, expected, md.digest());
    }

    // Byte buffer wrapping, read-only
    md.update(ByteBuffer.wrap(message).asReadOnlyBuffer());
    assertArrayEquals(alg + "-ByteBuffer-Wrap-RO", expected, md.digest());

    for (final int length : lengths) {
      for (int x = 0; x < message.length; x += length) {
        final int len = x + length > message.length ? message.length - x : length;
        md.update(ByteBuffer.wrap(message, x, len).asReadOnlyBuffer());
      }
      assertArrayEquals(alg + "-ByteBuffer-Wrap-RO-" + length, expected, md.digest());
    }

    // Byte buffer non-direct
    ByteBuffer bbuff = ByteBuffer.allocate(message.length);
    bbuff.put(message);
    bbuff.flip();
    md.update(bbuff);
    assertArrayEquals(alg + "-ByteBuffer-NonDirect", expected, md.digest());

    for (final int length : lengths) {
      bbuff = ByteBuffer.allocate(length);
      for (int x = 0; x < message.length; x += length) {
        final int len = x + length > message.length ? message.length - x : length;
        bbuff.clear();
        bbuff.put(message, x, len);
        bbuff.flip();
        md.update(bbuff);
      }
      assertArrayEquals(alg + "-ByteBuffer-NonDirect-" + length, expected, md.digest());
    }

    // Byte buffer direct
    bbuff = ByteBuffer.allocateDirect(message.length);
    bbuff.put(message);
    bbuff.flip();
    md.update(bbuff);
    assertArrayEquals(alg + "-ByteBuffer-Direct", expected, md.digest());

    for (final int length : lengths) {
      bbuff = ByteBuffer.allocateDirect(length);
      for (int x = 0; x < message.length; x += length) {
        final int len = x + length > message.length ? message.length - x : length;
        bbuff.clear();
        bbuff.put(message, x, len);
        bbuff.flip();
        md.update(bbuff);
      }
      assertArrayEquals(alg + "-ByteBuffer-Direct-" + length, expected, md.digest());
    }

    // Byte buffer direct, read-only
    bbuff = ByteBuffer.allocateDirect(message.length);
    bbuff.put(message);
    bbuff.flip();
    md.update(bbuff.asReadOnlyBuffer());
    assertArrayEquals(alg + "-ByteBuffer-Direct", expected, md.digest());

    for (final int length : lengths) {
      bbuff = ByteBuffer.allocateDirect(length);
      for (int x = 0; x < message.length; x += length) {
        final int len = x + length > message.length ? message.length - x : length;
        bbuff.clear();
        bbuff.put(message, x, len);
        bbuff.flip();
        md.update(bbuff.asReadOnlyBuffer());
      }
      assertArrayEquals(alg + "-ByteBuffer-Direct-" + length, expected, md.digest());
    }
  }

  /** A byte buffer guaranteed to have nothing but zeros to allow for faster zerorization. */
  private static final ByteBuffer ZERO_BYTE_BUF = ByteBuffer.allocate(8192).asReadOnlyBuffer();

  /**
   * Clears (zeros) all data in the buffer. Disregards position and limit; the entire capacity of
   * the buffer will be erased.
   *
   * @param buffer
   */
  static void zeroByteBuffer(ByteBuffer buffer) {
    buffer = buffer.duplicate();
    buffer.clear();

    while (buffer.hasRemaining()) {
      ByteBuffer src = ZERO_BYTE_BUF.duplicate();
      src.limit(Math.min(src.remaining(), buffer.remaining()));

      buffer.put(src);
    }
  }

  private static KeyFactory getKeyFactory(
      final AmazonCorrettoCryptoProvider provider, final String algorithm)
      throws NoSuchAlgorithmException {
    final EvpKeyType type = EvpKeyType.fromJceName(algorithm);
    if (type != null) {
      return provider.getKeyFactory(type);
    } else {
      return KeyFactory.getInstance(algorithm);
    }
  }

  static <E extends Enum<E>> void optionsFromProperty(
      final Class<E> clazz, final EnumSet<E> set, final String propertyName) {
    final String propertyValue = Loader.getProperty(propertyName, "");
    if (propertyValue.equalsIgnoreCase("help")) {
      System.err.format(
          "Valid values for %s%s are: %s or ALL",
          Loader.PROPERTY_BASE, propertyName, EnumSet.allOf(clazz));
    }
    final String[] extraCheckOptions = propertyValue.split(",");
    for (final String check : extraCheckOptions) {
      if (check.equalsIgnoreCase("all")) {
        set.addAll(EnumSet.allOf(clazz));
        break;
      }
      try {
        final E value = Enum.valueOf(clazz, check.toUpperCase());
        if (value != null) {
          set.add(value);
        }
      } catch (Exception ex) {
        // Ignore
      }
    }
  }

  private static int JAVA_VERSION = 0;

  static int getJavaVersion() {
    if (JAVA_VERSION > 0) {
      return JAVA_VERSION;
    }
    final String strVersion =
        AccessController.doPrivileged(
            (PrivilegedAction<String>) () -> System.getProperty("java.specification.version"));
    try {
      final String[] parts = strVersion.split("\\.");
      if (parts[0].equals("1")) {
        JAVA_VERSION = Integer.parseInt(parts[1]);
      } else {
        JAVA_VERSION = Integer.parseInt(parts[0]);
      }
    } catch (final RuntimeException ex) {
      LOG.warning("Unable to parse version string: " + strVersion);
      JAVA_VERSION = 8; // fallback to something safe
    }
    return JAVA_VERSION;
  }

  static boolean getBooleanProperty(String propertyName, boolean defaultValue) {
    final String defaultStr = defaultValue ? "true" : "false";
    final String propertyStr = Loader.getProperty(propertyName, defaultStr).toLowerCase();
    if (!propertyStr.equals("true") && !propertyStr.equals("false")) {
      LOG.warning(
          String.format(
              "Valid values for %s are false and true, with %s as default",
              propertyName, defaultStr));
      return defaultValue;
    }
    return Boolean.parseBoolean(propertyStr);
  }

  static void checkArrayLimits(final byte[] bytes, final int offset, final int length) {
    if (bytes == null) {
      throw new IllegalArgumentException("Bad argument: bytes cannot be null.");
    }

    if (offset < 0 || length < 0) {
      throw new ArrayIndexOutOfBoundsException("Negative offset or length");
    }

    if ((long) offset + (long) length > bytes.length) {
      throw new ArrayIndexOutOfBoundsException(
          "Requested range is outside of buffer limits"
              + bytes.length
              + ":"
              + offset
              + ":"
              + length);
    }
  }

  static <T> T requireNonNull(final T obj, final String message) {
    if (obj == null) throw new IllegalArgumentException(message);
    return obj;
  }

  static String requireNonNullString(final String s, final String message) {
    return requireNonNull(s, message);
  }

  enum NativeContextReleaseStrategy {
    HYBRID,
    LAZY,
    EAGER
  }

  private static NativeContextReleaseStrategy getNativeContextReleaseStrategyProperty(
      final String propertyName) {
    final String propertyStr = Loader.getProperty(propertyName, "HYBRID").toUpperCase();
    if (propertyStr.equals("LAZY")) {
      return NativeContextReleaseStrategy.LAZY;
    }
    if (propertyStr.equals("EAGER")) {
      return NativeContextReleaseStrategy.EAGER;
    }
    if (!propertyStr.equals("HYBRID")) {
      LOG.warning(
          String.format(
              "Valid values for %s are HYBRID, LAZY, EAGER, with HYBRID as default", propertyName));
    }
    return NativeContextReleaseStrategy.HYBRID;
  }

  static NativeContextReleaseStrategy getNativeContextReleaseStrategyProperty() {
    return getNativeContextReleaseStrategyProperty(PROPERTY_NATIVE_CONTEXT_RELEASE_STRATEGY);
  }

  static native void releaseEvpCipherCtx(long ctxPtr);

  public static byte[] checkAesKey(final Key key) throws InvalidKeyException {
    if (key == null) {
      throw new InvalidKeyException("Key can't be null");
    }
    if (!(key instanceof SecretKey)) {
      throw new InvalidKeyException("Need a SecretKey");
    }
    if (!"RAW".equalsIgnoreCase(key.getFormat())) {
      throw new InvalidKeyException("Need a raw format key");
    }
    if (!"AES".equalsIgnoreCase(key.getAlgorithm())) {
      throw new InvalidKeyException("Expected an AES key");
    }

    final byte[] encodedKey = key.getEncoded();
    if (encodedKey == null) {
      throw new InvalidKeyException("Key doesn't support encoding");
    }

    if (encodedKey.length != 128 / 8
        && encodedKey.length != 192 / 8
        && encodedKey.length != 256 / 8) {
      throw new InvalidKeyException(
          "Bad key length of " + (encodedKey.length * 8) + " bits; expected 128, 192, or 256 bits");
    }
    return encodedKey;
  }
}
