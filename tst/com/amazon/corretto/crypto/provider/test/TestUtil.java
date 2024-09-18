// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Random;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import java.util.zip.GZIPInputStream;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assumptions;

@SuppressWarnings("unchecked")
public class TestUtil {
  public static final String RESOURCE_REFLECTION = "REFLECTIVE_TOOLS";
  public static final String RESOURCE_PROVIDER = "JCE_PROVIDER";
  /**
   * Pseudo-resource used by ACCP tests to enforce that certain tests run by themselves. All tests
   * should takea "READ" lock on this resource. Tests which require exclusive control should take a
   * "READ_WRITE" lock.
   */
  public static final String RESOURCE_GLOBAL = "GLOBAL_TEST_LOCK";

  static final byte[] EMPTY_ARRAY = new byte[0];

  static SecretKeyFactory getHkdfSecretKeyFactory(final String digest) {
    try {
      return SecretKeyFactory.getInstance("HkdfWith" + digest, TestUtil.NATIVE_PROVIDER);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  public static final BouncyCastleProvider BC_PROVIDER = new BouncyCastleProvider();
  public static final AmazonCorrettoCryptoProvider NATIVE_PROVIDER =
      AmazonCorrettoCryptoProvider.INSTANCE;
  public static final String NATIVE_PROVIDER_PACKAGE =
      NATIVE_PROVIDER
          .getClass()
          .getName()
          .substring(0, NATIVE_PROVIDER.getClass().getName().lastIndexOf("."));

  public static final String[][] KNOWN_CURVES =
      new String[][] {
        new String[] {
          "secp256r1", "NIST P-256", "X9.62 prime256v1", /* "prime256v1", */ "1.2.840.10045.3.1.7"
        },
        new String[] {"secp384r1", "NIST P-384", "1.3.132.0.34"},
        new String[] {"secp521r1", "NIST P-521", "1.3.132.0.35"},
      };

  // Not supported in JDK17
  public static final String[][] LEGACY_CURVES =
      new String[][] {
        // Prime Curves
        new String[] {"secp224r1", "NIST P-224", "1.3.132.0.33"},
        new String[] {"secp256k1", "1.3.132.0.10"},
      };

  public static boolean isFips() {
    return NATIVE_PROVIDER.isFips();
  }

  public static boolean isExperimentalFips() {
    return NATIVE_PROVIDER.isExperimentalFips();
  }

  public static boolean supportsExtraKdfs() {
    return isExperimentalFips() || !isFips();
  }

  public static byte[] intArrayToByteArray(final int[] array) {
    final byte[] result = new byte[array.length];
    for (int i = 0; i != array.length; i++) {
      if (array[i] < 0 || array[i] > 255) {
        throw new IllegalArgumentException("The byte value must be in rage of [0, 256).");
      }
      result[i] = (byte) array[i];
    }
    return result;
  }

  public static boolean intArrayIsEqualToByteArray(final int[] expected, final byte[] actual) {
    if (expected.length != actual.length) {
      return false;
    }
    for (int i = 0; i != expected.length; i++) {
      final int v = actual[i] & 0xFF;
      if (expected[i] != v) {
        return false;
      }
    }
    return true;
  }

  public static String getCurveOid(String nameOrOid) {
    if (nameOrOid == null) {
      return null;
    }
    switch (nameOrOid) {
      case "secp224r1":
        return "1.3.132.0.33";
      case "prime256v1":
      case "secp256r1":
        return "1.2.840.10045.3.1.7";
      case "secp256k1":
        return "1.3.132.0.10";
      case "secp384r1":
        return "1.3.132.0.34";
      case "secp521r1":
        return "1.3.132.0.35";
      default:
        return nameOrOid; // if no known curve was specified, assume it's an OID
    }
  }

  public static boolean isOid(String name) {
    return name.matches("^[\\d\\.]+$");
  }

  /**
   * Thread local instances of SecureRandom with no further guarantees about implementation or
   * security.
   *
   * <p>These are only used for testing purposes and are configured specifically for speed rather
   * than security.
   */
  public static final ThreadLocal<SecureRandom> MISC_SECURE_RANDOM =
      ThreadLocal.withInitial(
          () -> {
            try {
              // We need something non-blocking and very fast which doesn't depend on our own
              // implementation.
              return SecureRandom.getInstance("SHA1PRNG");
            } catch (final NoSuchAlgorithmException ex) {
              throw new AssertionError(ex);
            }
          });

  private static final File TEST_DIR = new File(System.getProperty("test.data.dir", "."));

  public static byte[] getRandomBytes(int length) {
    final byte[] result = new byte[length];
    MISC_SECURE_RANDOM.get().nextBytes(result);
    return result;
  }

  public static void assertArraysHexEquals(byte[] expected, byte[] actual) {
    final String expectedHex = Hex.encodeHexString(expected);
    final String actualHex = Hex.encodeHexString(actual);
    assertEquals(expectedHex, actualHex);
  }

  public static void assertThrows(Class<? extends Throwable> expected, ThrowingRunnable callable) {
    try {
      callable.run();
    } catch (Throwable t) {
      if (expected.isAssignableFrom(t.getClass())) {
        return;
      }

      throw new AssertionError("Unexpected exception: " + t, t);
    }

    fail("Expected " + expected);
  }

  public static void assertThrows(
      Class<? extends Throwable> expected, String expectedMessage, ThrowingRunnable callable) {
    try {
      callable.run();
    } catch (Throwable t) {
      if (expected.isAssignableFrom(t.getClass()) && t.getMessage().equals(expectedMessage)) {
        return;
      }

      throw new AssertionError("Unexpected exception: " + t, t);
    }

    fail("Expected " + expected);
  }

  // We need to access some package-private methods to verify that we perform proper bounds checks,
  // etc, without
  // help from the JCE builtin Cipher classes. Unfortunately, the test classes cannot live in the
  // same package as
  // the signed JAR, so we need to use reflection to cross the package boundary here.
  public static void disableByteBufferReflection() {
    try {
      Class<?> klass = Class.forName("com.amazon.corretto.crypto.provider.ReflectiveTools");
      Method m = klass.getDeclaredMethod("disableByteBufferReflection");
      m.setAccessible(true);

      m.invoke(null);
    } catch (Exception e) {
      throw new Error(e);
    }
  }

  public static void enableByteBufferReflection() {
    try {
      Class<?> klass = Class.forName("com.amazon.corretto.crypto.provider.ReflectiveTools");
      Method m = klass.getDeclaredMethod("enableByteBufferReflection");
      m.setAccessible(true);

      m.invoke(null);
    } catch (Exception e) {
      throw new Error(e);
    }
  }

  public static int sneakyInvoke_int(Object o, String methodName, Object... args) throws Throwable {
    return (Integer) sneakyInvoke(o, methodName, args);
  }

  public static boolean sneakyInvoke_boolean(Object o, String methodName, Object... args)
      throws Throwable {
    return (Boolean) sneakyInvoke(o, methodName, args);
  }

  public static <T> T sneakyInvoke(Object o, String methodName, Object... args) throws Throwable {
    Class<?> klass;
    Object receiver;

    if (o instanceof Class) {
      klass = (Class<?>) o;
      receiver = null;
    } else {
      klass = o.getClass();
      receiver = o;
    }

    return sneakyInvokeExplicit(klass, methodName, receiver, args);
  }

  public static <T> T sneakyInvokeExplicit(
      Class<?> klass, final String methodName, final Object receiver, final Object... args)
      throws Throwable {
    while (klass != null) {
      for (Method m : klass.getDeclaredMethods()) {
        if (!m.getName().equals(methodName)) continue;

        if (argsCompatible(m.getParameterTypes(), args)) {
          try {
            m.setAccessible(true);
            return (T) m.invoke(receiver, args);
          } catch (InvocationTargetException e) {
            throw e.getCause();
          }
        }
      }
      klass = klass.getSuperclass();
    }
    throw new NoSuchMethodException("Can't find match for method");
  }

  public static Object sneakyConstruct(String className, Object... args) throws Throwable {
    final Class<?> klass = Class.forName(className);
    for (final Constructor<?> c : klass.getDeclaredConstructors()) {
      if (argsCompatible(c.getParameterTypes(), args)) {
        try {
          c.setAccessible(true);
          return c.newInstance(args);
        } catch (InvocationTargetException ex) {
          throw ex.getCause();
        }
      }
    }
    throw new Error("Can't find match for method");
  }

  public static InputStream sneakyGetTestData(String fileName) {
    try {
      Class<?> klass = Class.forName("com.amazon.corretto.crypto.provider.Loader");
      return (InputStream) sneakyInvoke(klass, "getTestData", fileName);
    } catch (Throwable e) {
      throw new Error(e);
    }
  }

  public static boolean argsCompatible(final Class<?>[] parameterTypes, final Object[] args) {
    if (parameterTypes.length != args.length) {
      return false;
    }

    boolean argsMatch = true;
    for (int i = 0; i < parameterTypes.length && argsMatch; i++) {
      Class<?> parameterType = parameterTypes[i];
      if (args[i] == null) {
        argsMatch = !parameterType.isPrimitive();
        continue;
      }

      Class<?> argsType = args[i].getClass();
      if (parameterType.isPrimitive() && argsType.getPackage().getName().equals("java.lang")) {
        // See if the corresponding boxed type is passed in

        try {
          Field f = argsType.getField("TYPE");
          if (f.get(null) == parameterType) continue;
        } catch (Exception e) {
          // nope, fall through to the isAssignableFrom check
        }
      }

      if (!parameterType.isAssignableFrom(argsType)) {
        argsMatch = false;
        break;
      }
    }
    return argsMatch;
  }

  public static byte[] arrayOf(final byte b, final int len) {
    final byte[] result = new byte[len];
    Arrays.fill(result, b);
    return result;
  }

  public static byte[] decodeHex(String hex) {
    if (hex == null) {
      return new byte[0];
    }
    if (hex.length() % 2 != 0) {
      throw new IllegalArgumentException("Input length must be even");
    }
    byte[] result = new byte[hex.length() / 2];
    for (int x = 0; x < hex.length() / 2; x++) {
      result[x] = (byte) Integer.parseInt(hex.substring(2 * x, 2 * x + 2), 16);
    }
    return result;
  }

  public static InputStream getTestData(final String fileName) throws IOException {
    return new FileInputStream(new File(TEST_DIR, fileName));
  }

  public static Object sneakyGetField(final Object object, final String fieldName) {
    Field field;
    Object instance;

    if (object instanceof Class) {
      instance = null;
      field = findField(fieldName, (Class<?>) object);
    } else {
      instance = object;
      field = findField(fieldName, object.getClass());
    }

    field.setAccessible(true);

    try {
      return field.get(instance);
    } catch (IllegalAccessException e) {
      throw new RuntimeException(e);
    }
  }

  public static Class<?> sneakyGetInternalClass(final Class<?> parent, final String name)
      throws ClassNotFoundException {
    for (Class<?> clazz : parent.getDeclaredClasses()) {
      if (clazz.getSimpleName().equals(name)) {
        return clazz;
      }
    }
    throw new ClassNotFoundException(String.format("No inner class %s of %s found", name, parent));
  }

  private static Field findField(final String fieldName, Class<?> klass) {
    Field field = null;
    while (true) {
      try {
        field = klass.getDeclaredField(fieldName);
        break;
      } catch (NoSuchFieldException e) {
        // proceed to superclass
        klass = klass.getSuperclass();
        if (klass == null) {
          throw new IllegalArgumentException("Couldn't find field " + fieldName);
        }
      }
    }
    return field;
  }

  public static int versionCompare(String a, Provider provider) {
    return versionCompare(a, getProviderVersion(provider));
  }

  public static int versionCompare(String a, String b) {
    final String[] aParts = a.split("\\.");
    final String[] bParts = b.split("\\.");
    final int limit = Math.min(aParts.length, bParts.length);
    for (int x = 0; x < limit; x++) {
      int tmp = Integer.compare(Integer.parseInt(aParts[x]), Integer.parseInt(bParts[x]));
      if (tmp != 0) {
        return tmp;
      }
    }
    return Integer.compare(aParts.length, bParts.length);
  }

  private static String getProviderVersion(Provider provider) {
    try {
      return (String) sneakyInvoke(provider, "getVersionStr");
    } catch (final Throwable e) {
      return Double.toString(provider.getVersion());
    }
  }

  public static void assumeMinimumVersion(String minVersion, Provider provider) {
    String providerVersion = getProviderVersion(provider);
    Assumptions.assumeTrue(
        versionCompare(minVersion, providerVersion) <= 0,
        String.format("Required version %s, Actual version %s", minVersion, providerVersion));
  }

  public static int getJavaVersion() {
    final String[] parts = System.getProperty("java.specification.version").split("\\.");
    if (parts[0].equals("1")) {
      return Integer.parseInt(parts[1]);
    }
    return Integer.parseInt(parts[0]);
  }

  public static void assumeMinimumJavaVersion(int minVersion) {
    Assumptions.assumeTrue(getJavaVersion() >= minVersion);
  }

  public static synchronized Provider[] saveProviders() {
    return Security.getProviders();
  }

  public static synchronized void restoreProviders(final Provider[] providers) {
    if (Arrays.equals(providers, Security.getProviders())) {
      return;
    }
    for (Provider oldProvider : Security.getProviders()) {
      Security.removeProvider(oldProvider.getName());
    }
    for (Provider provider : providers) {
      Security.addProvider(provider);
    }
  }

  public static Stream<RspTestEntry> getEntriesFromFile(
      final String fileName, final boolean isCompressed) throws IOException {
    final File rsp = new File(System.getProperty("test.data.dir"), fileName);
    final InputStream is =
        isCompressed ? new GZIPInputStream(new FileInputStream(rsp)) : new FileInputStream(rsp);
    final Iterator<RspTestEntry> iterator =
        RspTestEntry.iterateOverResource(is, true); // Auto-closes stream
    final Spliterator<RspTestEntry> split =
        Spliterators.spliteratorUnknownSize(iterator, Spliterator.ORDERED);
    return StreamSupport.stream(split, false);
  }

  public static Stream<RspTestEntry> getEntriesFromFile(final String fileName) throws IOException {
    return getEntriesFromFile(fileName, true);
  }

  public static int roundUp(final int i, final int m) {
    final int d = m - (i % m);
    return d == m ? i : (i + d);
  }

  public static byte[] genData(final long seed, final int len) {
    final byte[] result = new byte[len];
    final Random rand = new Random(seed);
    rand.nextBytes(result);
    return result;
  }

  public static ByteBuffer genData(
      final long seed, final int offset, final int len, boolean isDirect) {
    final byte[] data = genData(seed, offset + len);
    final ByteBuffer result =
        isDirect ? ByteBuffer.allocateDirect(data.length) : ByteBuffer.allocate(data.length);
    return (ByteBuffer) result.put(data).position(offset);
  }

  public static ByteBuffer genData(final long seed, final int len, boolean isDirect) {
    return genData(seed, 0, len, isDirect);
  }

  public static IvParameterSpec genIv(final long seed, final int len) {
    return new IvParameterSpec(genData(seed, len));
  }

  public static SecretKeySpec genAesKey(final long seed, final int len) {
    return new SecretKeySpec(genData(seed, len / 8), "AES");
  }

  public static boolean byteBuffersAreEqual(final ByteBuffer a, final ByteBuffer b) {
    return byteBuffersAreEqual(a, Arrays.asList(b));
  }

  public static boolean byteBuffersAreEqual(final ByteBuffer a, final List<ByteBuffer> chunks) {
    final int chunksTotalLen =
        chunks.stream().map(c -> c == null ? 0 : c.remaining()).reduce(0, Integer::sum);

    if (a.remaining() != chunksTotalLen) {
      return false;
    }
    int aIndex = a.position();
    for (final ByteBuffer chunk : chunks) {
      if (chunk == null) continue;
      for (int chunkIndex = chunk.position(); chunkIndex != chunk.limit(); chunkIndex++) {
        if (a.get(aIndex) != chunk.get(chunkIndex)) return false;
        aIndex++;
      }
    }
    return true;
  }

  public static byte[] mergeByteArrays(final List<byte[]> chunks) {
    final int len = chunks.stream().map(c -> c == null ? 0 : c.length).reduce(0, Integer::sum);

    final byte[] result = new byte[len];

    int offset = 0;
    for (final byte[] chunk : chunks) {
      if (chunk == null) continue;
      System.arraycopy(chunk, 0, result, offset, chunk.length);
      offset += chunk.length;
    }

    return result;
  }

  public static ByteBuffer mergeByteBuffers(final List<ByteBuffer> chunks) {
    final int len = chunks.stream().map(c -> c == null ? 0 : c.remaining()).reduce(0, Integer::sum);

    final ByteBuffer result = ByteBuffer.allocate(len);

    for (final ByteBuffer chunk : chunks) {
      if (chunk == null) continue;
      result.put(chunk);
    }

    result.flip();

    return result;
  }

  public static List<Integer> constantPattern(final int inputLen, final int c) {
    final List<Integer> result = new ArrayList<>();
    int total = 0;
    while (total < inputLen) {
      result.add(c);
      total += c;
    }
    return result;
  }

  public static List<Integer> ascendingPattern(final int inputLen) {
    final List<Integer> result = new ArrayList<>();
    int i = 0;
    int total = 0;
    while (total < inputLen) {
      result.add(i);
      i++;
      total += i;
    }
    return result;
  }

  public static List<Integer> randomPattern(final int inputLen, final long seed) {
    final List<Integer> result = new ArrayList<>();
    final Random random = new Random(seed);
    int total = 0;
    while (total < inputLen) {
      final int c = random.nextInt(inputLen + 1);
      result.add(c);
      total += c;
    }
    return result;
  }

  public static ByteBuffer multiStepArray(
      final Cipher cipher, final List<Integer> process, final byte[] input) throws Exception {
    return multiStepArray(cipher, process, input, input.length);
  }

  public static ByteBuffer multiStepArray(
      final Cipher cipher, final List<Integer> process, final byte[] input, final int inputLen)
      throws Exception {

    final byte[] output = new byte[cipher.getOutputSize(inputLen)];

    int inputOffset = 0;
    int outputOffset = 0;

    for (final Integer p : process) {
      if (inputOffset == inputLen) break;
      final int toBeProcessed = (p + inputOffset) > inputLen ? (inputLen - inputOffset) : p;
      outputOffset += cipher.update(input, inputOffset, toBeProcessed, output, outputOffset);
      inputOffset += toBeProcessed;
    }

    if (inputOffset == inputLen) {
      outputOffset += cipher.doFinal(output, outputOffset);
    } else {
      outputOffset +=
          cipher.doFinal(input, inputOffset, inputLen - inputOffset, output, outputOffset);
    }

    return ByteBuffer.wrap(output, 0, outputOffset);
  }

  public static List<ByteBuffer> multiStepArrayMultiAllocationImplicit(
      final Cipher cipher, final List<Integer> process, final byte[] input) throws Exception {
    final List<ByteBuffer> outputChunks = new ArrayList<>();

    int inputOffset = 0;

    for (final Integer p : process) {
      if (inputOffset == input.length) break;
      final int toBeProcessed = (p + inputOffset) > input.length ? (input.length - inputOffset) : p;
      final byte[] chunk = cipher.update(input, inputOffset, toBeProcessed);
      // If input.length == 0, then javax.crypto.Cipher::update returns null.
      if (chunk != null) {
        outputChunks.add(ByteBuffer.wrap(chunk));
      }
      inputOffset += toBeProcessed;
    }

    if (inputOffset == input.length) {
      outputChunks.add(ByteBuffer.wrap(cipher.doFinal()));
    } else {
      outputChunks.add(
          ByteBuffer.wrap(cipher.doFinal(input, inputOffset, input.length - inputOffset)));
    }
    return outputChunks;
  }

  public static List<ByteBuffer> multiStepArrayMultiAllocationExplicit(
      final Cipher cipher, final List<Integer> process, final byte[] input) throws Exception {
    final List<ByteBuffer> outputChunks = new ArrayList<>();

    int inputOffset = 0;

    for (final Integer p : process) {
      if (inputOffset == input.length) break;
      final int toBeProcessed = (p + inputOffset) > input.length ? (input.length - inputOffset) : p;
      final byte[] temp = new byte[cipher.getOutputSize(toBeProcessed)];
      final int outputLen = cipher.update(input, inputOffset, toBeProcessed, temp, 0);
      outputChunks.add(ByteBuffer.wrap(temp, 0, outputLen));
      inputOffset += toBeProcessed;
    }

    final byte[] temp = new byte[cipher.getOutputSize(input.length - inputOffset)];

    final int outputLen;
    if (inputOffset == input.length) {
      outputLen = cipher.doFinal(temp, 0);
    } else {
      outputLen = cipher.doFinal(input, inputOffset, input.length - inputOffset, temp, 0);
    }
    outputChunks.add(ByteBuffer.wrap(temp, 0, outputLen));

    return outputChunks;
  }

  public static ByteBuffer oneShotByteBuffer(final Cipher cipher, final ByteBuffer input)
      throws Exception {
    final ByteBuffer output = ByteBuffer.allocate(cipher.getOutputSize(input.remaining()));
    cipher.doFinal(input, output);
    output.flip();
    return output;
  }

  public static ByteBuffer multiStepByteBuffer(
      final Cipher cipher,
      final List<Integer> process,
      final ByteBuffer input,
      final boolean outputDirect)
      throws Exception {
    final int cipherSize = cipher.getOutputSize(input.remaining());

    final ByteBuffer output =
        outputDirect ? ByteBuffer.allocateDirect(cipherSize) : ByteBuffer.allocate(cipherSize);

    for (final Integer p : process) {
      if (!input.hasRemaining()) break;
      final int toBeProcessed = p > input.remaining() ? input.remaining() : p;
      final ByteBuffer temp = input.duplicate();
      temp.limit(input.position() + toBeProcessed);
      cipher.update(temp, output);
      input.position(input.position() + toBeProcessed);
    }

    cipher.doFinal(input, output);

    output.flip();

    return output;
  }

  public static List<ByteBuffer> multiStepByteBufferMultiAllocation(
      final Cipher cipher,
      final List<Integer> process,
      final ByteBuffer input,
      final boolean outputDirect)
      throws Exception {

    final List<ByteBuffer> outputChunks = new ArrayList<>();

    for (final Integer p : process) {
      if (!input.hasRemaining()) break;
      final int toBeProcessed = p > input.remaining() ? input.remaining() : p;
      final int cipherSize = cipher.getOutputSize(toBeProcessed);
      final ByteBuffer output =
          outputDirect ? ByteBuffer.allocateDirect(cipherSize) : ByteBuffer.allocate(cipherSize);
      final ByteBuffer temp = input.duplicate();
      temp.limit(input.position() + toBeProcessed);
      cipher.update(temp, output);
      output.flip();
      outputChunks.add(output);
      input.position(input.position() + toBeProcessed);
    }

    final int cipherSize = cipher.getOutputSize(input.remaining());
    final ByteBuffer output =
        outputDirect ? ByteBuffer.allocateDirect(cipherSize) : ByteBuffer.allocate(cipherSize);
    cipher.doFinal(input, output);
    output.flip();
    outputChunks.add(output);

    return outputChunks;
  }

  public static ByteBuffer multiStepByteBufferInPlace(
      final Cipher cipher, final List<Integer> process, final ByteBuffer input) throws Exception {

    final ByteBuffer output = input.duplicate();
    output.limit(output.capacity());

    for (final Integer p : process) {
      if (!input.hasRemaining()) break;
      final int toBeProcessed = p > input.remaining() ? input.remaining() : p;
      final ByteBuffer temp = input.duplicate();
      temp.limit(input.position() + toBeProcessed);
      cipher.update(temp, output);
      input.position(input.position() + toBeProcessed);
    }

    cipher.doFinal(input, output);

    output.flip();

    return output;
  }
  // Returns the length of the output.
  public static int multiStepInPlaceArray(
      final Cipher cipher,
      final List<Integer> process,
      final byte[] inputOutput,
      final int inputLen)
      throws Exception {

    int inputOffset = 0;
    int outputOffset = 0;

    for (final Integer p : process) {
      if (inputOffset == inputLen) break;
      final int toBeProcessed = (p + inputOffset) > inputLen ? (inputLen - inputOffset) : p;
      outputOffset +=
          cipher.update(inputOutput, inputOffset, toBeProcessed, inputOutput, outputOffset);
      inputOffset += toBeProcessed;
    }

    if (inputOffset == inputLen) {
      outputOffset += cipher.doFinal(inputOutput, outputOffset);
    } else {
      outputOffset +=
          cipher.doFinal(
              inputOutput, inputOffset, inputLen - inputOffset, inputOutput, outputOffset);
    }

    return outputOffset;
  }

  public static List<Integer> genPattern(final long seed, final int choice, final int inputLen) {
    if (choice < 0) {
      return randomPattern(inputLen, seed);
    }
    if (choice == 0) {
      return ascendingPattern(inputLen);
    }
    return constantPattern(inputLen, choice);
  }

  static Digest bcDigest(final String digest) {
    switch (digest) {
      case "SHA1":
        return new SHA1Digest();
      case "SHA224":
        return new SHA224Digest();
      case "SHA256":
        return new SHA256Digest();
      case "SHA384":
        return new SHA384Digest();
      case "SHA512":
        return new SHA512Digest();
      default:
        return null;
    }
  }
}
