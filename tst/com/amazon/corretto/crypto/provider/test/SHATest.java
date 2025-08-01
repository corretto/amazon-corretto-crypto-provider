// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.zip.GZIPInputStream;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.SAME_THREAD)
@ResourceLock(value = TestUtil.RESOURCE_REFLECTION)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ_WRITE)
public class SHATest {

  private static final String SHA_1 = "SHA-1";
  private static final String SHA_256 = "SHA-256";
  private static final String SHA_384 = "SHA-384";
  private static final String SHA_512 = "SHA-512";
  private static final String SHA3_224 = "SHA3-224";
  private static final String SHA3_256 = "SHA3-256";
  private static final String SHA3_384 = "SHA3-384";
  private static final String SHA3_512 = "SHA3-512";

  private MessageDigest getDigest(String algo) throws Exception {
    return MessageDigest.getInstance(algo, TestUtil.NATIVE_PROVIDER);
  }

  // KATs vary by algo - HashMap setup for different test scenarios
  private static HashMap<String, String> nullDigestMap = new HashMap<>();
  private static HashMap<String, String> vectorMap = new HashMap<>();
  private static HashMap<String, String> fastPathMap = new HashMap<>();
  private static HashMap<String, String> nativeByteBufferMap = new HashMap<>();
  private static HashMap<String, String> cavpShortMap = new HashMap<>();
  private static HashMap<String, String> cavpLongMap = new HashMap<>();

  private static void nullDigestMapSetup() {
    nullDigestMap.put(SHA_1, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    nullDigestMap.put(SHA_256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    nullDigestMap.put(
        SHA_384,
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
    nullDigestMap.put(
        SHA_512,
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    nullDigestMap.put(SHA3_224, "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
    nullDigestMap.put(SHA3_256, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    nullDigestMap.put(
        SHA3_384,
        "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004");
    nullDigestMap.put(
        SHA3_512,
        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
  }

  private static void vectorMapSetup() {
    vectorMap.put(SHA_1, "dc724af18fbdd4e59189f5fe768a5f8311527050");
    vectorMap.put(SHA_256, "cf80cd8aed482d5d1527d7dc72fceff84e6326592848447d2dc0b0e87dfc9a90");
    vectorMap.put(
        SHA_384,
        "cf4811d74fd40504674fc3273f824fa42f755b9660a2e902b57f1df74873db1a91a037bcee65f1a88ecd1ef57ff254c9");
    vectorMap.put(
        SHA_512,
        "521b9ccefbcd14d179e7a1bb877752870a6d620938b28a66a107eac6e6805b9d0989f45b5730508041aa5e710847d439ea74cd312c9355f1f2dae08d40e41d50");
    vectorMap.put(SHA3_224, "04eaf0c175aa45299155aca3f97e41c2d684eb0978c9af6cd88c5a51");
    vectorMap.put(SHA3_256, "7f5979fb78f082e8b1c676635db8795c4ac6faba03525fb708cb5fd68fd40c5e");
    vectorMap.put(
        SHA3_384,
        "e15a44d4e12ac138db4b8d77e954d78d94de4391ec2d1d8b2b8ace1a2f4b3d2fb9efd0546d6fcafacbe5b1640639b005");
    vectorMap.put(
        SHA3_512,
        "881c7d6ba98678bcd96e253086c4048c3ea15306d0d13ff48341c6285ee71102a47b6f16e20e4d65c0c3d677be689dfda6d326695609cbadfafa1800e9eb7fc1");
  }

  private static void fastPathMapSetup() {
    fastPathMap.put(SHA_1, "dc724af18fbdd4e59189f5fe768a5f8311527050");
    fastPathMap.put(SHA_256, "cf80cd8aed482d5d1527d7dc72fceff84e6326592848447d2dc0b0e87dfc9a90");
    fastPathMap.put(
        SHA_384,
        "cf4811d74fd40504674fc3273f824fa42f755b9660a2e902b57f1df74873db1a91a037bcee65f1a88ecd1ef57ff254c9");
    fastPathMap.put(
        SHA_512,
        "521b9ccefbcd14d179e7a1bb877752870a6d620938b28a66a107eac6e6805b9d0989f45b5730508041aa5e710847d439ea74cd312c9355f1f2dae08d40e41d50");
    fastPathMap.put(SHA3_224, "04eaf0c175aa45299155aca3f97e41c2d684eb0978c9af6cd88c5a51");
    fastPathMap.put(SHA3_256, "7f5979fb78f082e8b1c676635db8795c4ac6faba03525fb708cb5fd68fd40c5e");
    fastPathMap.put(
        SHA3_384,
        "e15a44d4e12ac138db4b8d77e954d78d94de4391ec2d1d8b2b8ace1a2f4b3d2fb9efd0546d6fcafacbe5b1640639b005");
    fastPathMap.put(
        SHA3_512,
        "881c7d6ba98678bcd96e253086c4048c3ea15306d0d13ff48341c6285ee71102a47b6f16e20e4d65c0c3d677be689dfda6d326695609cbadfafa1800e9eb7fc1");
  }

  private static void nativeByteBufferMapSetup() {
    nativeByteBufferMap.put(SHA_1, "dc724af18fbdd4e59189f5fe768a5f8311527050");
    nativeByteBufferMap.put(
        SHA_256, "cf80cd8aed482d5d1527d7dc72fceff84e6326592848447d2dc0b0e87dfc9a90");
    nativeByteBufferMap.put(
        SHA_384,
        "cf4811d74fd40504674fc3273f824fa42f755b9660a2e902b57f1df74873db1a91a037bcee65f1a88ecd1ef57ff254c9");
    nativeByteBufferMap.put(
        SHA_512,
        "521b9ccefbcd14d179e7a1bb877752870a6d620938b28a66a107eac6e6805b9d0989f45b5730508041aa5e710847d439ea74cd312c9355f1f2dae08d40e41d50");
    nativeByteBufferMap.put(SHA3_224, "04eaf0c175aa45299155aca3f97e41c2d684eb0978c9af6cd88c5a51");
    nativeByteBufferMap.put(
        SHA3_256, "7f5979fb78f082e8b1c676635db8795c4ac6faba03525fb708cb5fd68fd40c5e");
    nativeByteBufferMap.put(
        SHA3_384,
        "e15a44d4e12ac138db4b8d77e954d78d94de4391ec2d1d8b2b8ace1a2f4b3d2fb9efd0546d6fcafacbe5b1640639b005");
    nativeByteBufferMap.put(
        SHA3_512,
        "881c7d6ba98678bcd96e253086c4048c3ea15306d0d13ff48341c6285ee71102a47b6f16e20e4d65c0c3d677be689dfda6d326695609cbadfafa1800e9eb7fc1");
  }

  private static void cavpShortMapSetup() {
    cavpShortMap.put(SHA_1, "SHA1ShortMsg.rsp.gz");
    cavpShortMap.put(SHA_256, "SHA256ShortMsg.rsp.gz");
    cavpShortMap.put(SHA_384, "SHA384ShortMsg.rsp.gz");
    cavpShortMap.put(SHA_512, "SHA512ShortMsg.rsp.gz");
    cavpShortMap.put(SHA3_224, "SHA3_224ShortMsg.rsp.gz");
    cavpShortMap.put(SHA3_256, "SHA3_256ShortMsg.rsp.gz");
    cavpShortMap.put(SHA3_384, "SHA3_384ShortMsg.rsp.gz");
    cavpShortMap.put(SHA3_512, "SHA3_512ShortMsg.rsp.gz");
  }

  private static void cavpLongMapSetup() {
    cavpLongMap.put(SHA_1, "SHA1LongMsg.rsp.gz");
    cavpLongMap.put(SHA_256, "SHA256LongMsg.rsp.gz");
    cavpLongMap.put(SHA_384, "SHA384LongMsg.rsp.gz");
    cavpLongMap.put(SHA_512, "SHA512LongMsg.rsp.gz");
    cavpLongMap.put(SHA3_224, "SHA3_224LongMsg.rsp.gz");
    cavpLongMap.put(SHA3_256, "SHA3_256LongMsg.rsp.gz");
    cavpLongMap.put(SHA3_384, "SHA3_384LongMsg.rsp.gz");
    cavpLongMap.put(SHA3_512, "SHA3_512LongMsg.rsp.gz");
  }

  static {
    nullDigestMapSetup();
    vectorMapSetup();
    fastPathMapSetup();
    nativeByteBufferMapSetup();
    cavpShortMapSetup();
    cavpLongMapSetup();
  }

  @ParameterizedTest
  @ValueSource(strings = {SHA_1, SHA_256, SHA_384, SHA_512, SHA3_224, SHA3_256, SHA3_384, SHA3_512})
  public void testNegativeLength(String algo) throws Exception {
    final byte[] data = new byte[32];
    final int start = 0;
    final int end = -31;

    final MessageDigest digest = getDigest(algo);

    assertThrows(
        IndexOutOfBoundsException.class,
        () -> {
          digest.update(data, start, end);
        });
  }

  @ParameterizedTest
  @ValueSource(strings = {SHA_1, SHA_256, SHA_384, SHA_512, SHA3_224, SHA3_256, SHA3_384, SHA3_512})
  public void testNullDigest(String algo) throws Exception {
    MessageDigest digest = getDigest(algo);
    assertArrayEquals(Hex.decodeHex(nullDigestMap.get(algo).toCharArray()), digest.digest());
    digest = getDigest(algo);
    digest.update(new byte[0]);
    assertArrayEquals(Hex.decodeHex(nullDigestMap.get(algo).toCharArray()), digest.digest());
    digest = getDigest(algo);
    digest.update(ByteBuffer.allocateDirect(0));
    assertArrayEquals(Hex.decodeHex(nullDigestMap.get(algo).toCharArray()), digest.digest());
  }

  @ParameterizedTest
  @ValueSource(strings = {SHA_1, SHA_256, SHA_384, SHA_512, SHA3_224, SHA3_256, SHA3_384, SHA3_512})
  public void testVector(String algo) throws Exception {
    MessageDigest digest = getDigest(algo);
    digest.update("testing".getBytes());

    assertArrayEquals(Hex.decodeHex(vectorMap.get(algo).toCharArray()), digest.digest());
  }

  @ParameterizedTest
  @ValueSource(strings = {SHA_1, SHA_256, SHA_384, SHA_512, SHA3_224, SHA3_256, SHA3_384, SHA3_512})
  public void testFastPath(String algo) throws Exception {
    MessageDigest digest = getDigest(algo);

    assertArrayEquals(
        Hex.decodeHex(fastPathMap.get(algo).toCharArray()), digest.digest("testing".getBytes()));
  }

  @ParameterizedTest
  @ValueSource(strings = {SHA_1, SHA_256, SHA_384, SHA_512, SHA3_224, SHA3_256, SHA3_384, SHA3_512})
  public void testNativeByteBuffer(String algo) throws Exception {
    byte[] testData = "testing".getBytes();
    ByteBuffer nativeBuf = ByteBuffer.allocateDirect(testData.length);
    nativeBuf.put(testData);
    nativeBuf.flip();

    MessageDigest digest = getDigest(algo);
    digest.update(nativeBuf);
    assertEquals(nativeBuf.position(), nativeBuf.limit());

    assertArrayEquals(Hex.decodeHex(nativeByteBufferMap.get(algo).toCharArray()), digest.digest());
  }

  @ParameterizedTest
  @ValueSource(strings = {SHA_1, SHA_256, SHA_384, SHA_512, SHA3_224, SHA3_256, SHA3_384, SHA3_512})
  public void testRandomly(String algo) throws Exception {
    // SHA3 is not exposed in SUN JDK8, so we can't test against it
    if (algo.equals(SHA3_224)
        || algo.equals(SHA3_256)
        || algo.equals(SHA3_384)
        || algo.equals(SHA3_512)) {
      TestUtil.assumeMinimumJavaVersion(11);
    }
    new HashFunctionTester(algo).testRandomly(1000);
  }

  @ParameterizedTest
  @ValueSource(strings = {SHA_1, SHA_256, SHA_384, SHA_512, SHA3_224, SHA3_256, SHA3_384, SHA3_512})
  public void testAPIDetails(String algo) throws Exception {
    // SHA3 is not exposed in SUN JDK8, so we can't test against it
    if (algo.equals(SHA3_224)
        || algo.equals(SHA3_256)
        || algo.equals(SHA3_384)
        || algo.equals(SHA3_512)) {
      TestUtil.assumeMinimumJavaVersion(11);
    }
    new HashFunctionTester(algo).testAPI();
  }

  @ParameterizedTest
  @ValueSource(strings = {SHA_1, SHA_256, SHA_384, SHA_512, SHA3_224, SHA3_256, SHA3_384, SHA3_512})
  public void cavpShortVectors(String algo) throws Throwable {
    try (final InputStream is = new GZIPInputStream(TestUtil.getTestData(cavpShortMap.get(algo)))) {
      new HashFunctionTester(algo).test(RspTestEntry.iterateOverResource(is));
    }
  }

  @ParameterizedTest
  @ValueSource(strings = {SHA_1, SHA_256, SHA_384, SHA_512, SHA3_224, SHA3_256, SHA3_384, SHA3_512})
  public void cavpLongVectors(String algo) throws Throwable {
    try (final InputStream is = new GZIPInputStream(TestUtil.getTestData(cavpLongMap.get(algo)))) {
      new HashFunctionTester(algo).test(RspTestEntry.iterateOverResource(is));
    }
  }
}
