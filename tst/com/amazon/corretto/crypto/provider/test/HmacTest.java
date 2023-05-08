// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.NATIVE_PROVIDER;
import static com.amazon.corretto.crypto.provider.test.TestUtil.NATIVE_PROVIDER_PACKAGE;
import static com.amazon.corretto.crypto.provider.test.TestUtil.assertArraysHexEquals;
import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyInvoke;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.amazon.corretto.crypto.provider.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Provider.Service;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.zip.GZIPInputStream;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class HmacTest {
  private static final Class<?> UTILS_CLASS;
  private static final List<String> SUPPORTED_HMACS;

  static {
    List<String> macs = new ArrayList<>();
    for (final Service s : NATIVE_PROVIDER.getServices()) {
      if (s.getType().equals("Mac") && s.getAlgorithm().startsWith("Hmac")) {
        macs.add(s.getAlgorithm());
      }
    }
    SUPPORTED_HMACS = Collections.unmodifiableList(macs);
    try {
      UTILS_CLASS = Class.forName("com.amazon.corretto.crypto.provider.Utils");
    } catch (final ClassNotFoundException ex) {
      throw new AssertionError(ex);
    }
  }

  private static List<String> supportedHmacs() {
    return SUPPORTED_HMACS;
  }

  @Test
  public void requireInitialization() throws GeneralSecurityException {
    final Mac hmac = Mac.getInstance("HmacSHA256", NATIVE_PROVIDER);
    assertThrows(
        IllegalStateException.class,
        () -> hmac.update("This should fail".getBytes(StandardCharsets.US_ASCII)));
  }

  // The algorithm on the key must be ignored for compatibility with existing JCE implementations
  // such as SUN and BouncyCastle
  public void wrongAlgorithmWorks() throws GeneralSecurityException {
    final Mac hmac = Mac.getInstance("HmacSHA256", NATIVE_PROVIDER);
    final SecretKeySpec key =
        new SecretKeySpec("YellowSubmarine".getBytes(StandardCharsets.US_ASCII), "AES");
    hmac.init(key);
  }

  @Test
  public void badParams() throws GeneralSecurityException {
    final Mac hmac = Mac.getInstance("HmacSHA256", NATIVE_PROVIDER);
    final SecretKeySpec key =
        new SecretKeySpec("YellowSubmarine".getBytes(StandardCharsets.US_ASCII), "HmacSHA256");
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> hmac.init(key, new IvParameterSpec(new byte[16])));
  }

  private void testMac(Mac mac, SecretKey key, byte[] message, byte[] expected) throws Throwable {
    sneakyInvoke(UTILS_CLASS, "testMac", mac, key, message, expected);
  }

  @Test
  public void knownValue() throws Throwable {
    try (final Scanner in =
        new Scanner(TestUtil.sneakyGetTestData("hmac.txt"), StandardCharsets.US_ASCII.name())) {
      while (in.hasNext()) {
        final String type = in.next();
        SecretKey key = new SecretKeySpec(Hex.decodeHex(in.next().toCharArray()), "HMAC");
        byte[] message = Hex.decodeHex(in.next().toCharArray());
        switch (type) {
          case "sha2":
            testMac(
                Mac.getInstance("HmacSHA256", NATIVE_PROVIDER),
                key,
                message,
                Hex.decodeHex(in.next().toCharArray()));
            testMac(
                Mac.getInstance("HmacSHA384", NATIVE_PROVIDER),
                key,
                message,
                Hex.decodeHex(in.next().toCharArray()));
            testMac(
                Mac.getInstance("HmacSHA512", NATIVE_PROVIDER),
                key,
                message,
                Hex.decodeHex(in.next().toCharArray()));
            break;
          case "sha1":
            testMac(
                Mac.getInstance("HmacSHA1", NATIVE_PROVIDER),
                key,
                message,
                Hex.decodeHex(in.next().toCharArray()));
            break;
          case "md5":
            testMac(
                Mac.getInstance("HmacMD5", NATIVE_PROVIDER),
                key,
                message,
                Hex.decodeHex(in.next().toCharArray()));
            break;
          default:
            throw new UnsupportedOperationException("Not yet built");
        }
      }
    }
  }

  @ParameterizedTest
  @MethodSource("supportedHmacs")
  // Suppress redundant cast warnings; they're redundant in java 9 but not java 8
  @SuppressWarnings({"cast", "RedundantCast"})
  public void emptyHmac(final String algorithm) throws Exception {
    final SecretKeySpec key =
        new SecretKeySpec("YellowSubmarine".getBytes(StandardCharsets.US_ASCII), "Generic");
    final Mac jceMac = Mac.getInstance(algorithm, "SunJCE");
    jceMac.init(key);
    final byte[] expected = jceMac.doFinal();

    Mac nativeMac = Mac.getInstance(algorithm, NATIVE_PROVIDER);
    nativeMac.init(key);
    assertArrayEquals(expected, nativeMac.doFinal());

    nativeMac = Mac.getInstance(algorithm, NATIVE_PROVIDER);
    nativeMac.init(key);
    nativeMac.update(new byte[0]);
    assertArrayEquals(expected, nativeMac.doFinal());

    nativeMac = Mac.getInstance(algorithm, NATIVE_PROVIDER);
    nativeMac.init(key);
    nativeMac.update((ByteBuffer) ByteBuffer.allocateDirect(4).limit(0));
    assertArrayEquals(expected, nativeMac.doFinal());
  }

  // These tests purposefully uses large enough data to bypass our internal buffering logic and
  // force
  // multiple calls to the native layer.
  @ParameterizedTest
  @MethodSource("supportedHmacs")
  public void largeArrayMsgs(final String algorithm) throws Exception {
    final byte[] msg = new byte[256];
    for (int x = 0; x < msg.length; x++) {
      msg[x] = (byte) x;
    }
    final SecretKeySpec key =
        new SecretKeySpec("YellowSubmarine".getBytes(StandardCharsets.US_ASCII), "Generic");
    final Mac nativeMac = Mac.getInstance(algorithm, NATIVE_PROVIDER);
    final Mac jceMac = Mac.getInstance(algorithm, "SunJCE");
    nativeMac.init(key);
    jceMac.init(key);
    for (int x = 0; x < 41; x++) {
      nativeMac.update(msg);
      jceMac.update(msg);
    }
    assertArrayEquals(jceMac.doFinal(), nativeMac.doFinal());
  }

  @ParameterizedTest
  @MethodSource("supportedHmacs")
  public void largeBufferMsgs(final String algorithm) throws Exception {
    final ByteBuffer msg = ByteBuffer.allocate(256);
    for (int x = 0; x < msg.capacity(); x++) {
      msg.put((byte) x);
    }
    msg.flip();
    final SecretKeySpec key =
        new SecretKeySpec("YellowSubmarine".getBytes(StandardCharsets.US_ASCII), "Generic");
    final Mac nativeMac = Mac.getInstance(algorithm, NATIVE_PROVIDER);
    final Mac jceMac = Mac.getInstance(algorithm, "SunJCE");
    nativeMac.init(key);
    jceMac.init(key);
    for (int x = 0; x < 41; x++) {
      nativeMac.update(msg.duplicate());
      jceMac.update(msg.duplicate());
    }
    assertArrayEquals(jceMac.doFinal(), nativeMac.doFinal());
  }

  @ParameterizedTest
  @MethodSource("supportedHmacs")
  public void largeDirectBufferMsgs(final String algorithm) throws Exception {
    final ByteBuffer msg = ByteBuffer.allocateDirect(256);
    for (int x = 0; x < msg.capacity(); x++) {
      msg.put((byte) x);
    }
    msg.flip();
    final SecretKeySpec key =
        new SecretKeySpec("YellowSubmarine".getBytes(StandardCharsets.US_ASCII), "Generic");
    final Mac nativeMac = Mac.getInstance(algorithm, NATIVE_PROVIDER);
    final Mac jceMac = Mac.getInstance(algorithm, "SunJCE");
    nativeMac.init(key);
    jceMac.init(key);
    for (int x = 0; x < 41; x++) {
      nativeMac.update(msg.duplicate());
      jceMac.update(msg.duplicate());
    }
    assertArrayEquals(jceMac.doFinal(), nativeMac.doFinal());
  }

  @ParameterizedTest
  @MethodSource("supportedHmacs")
  public void largeChunkArrayMsgs(final String algorithm) throws Exception {
    final byte[] msg = new byte[4096];
    for (int x = 0; x < msg.length; x++) {
      msg[x] = (byte) x;
    }
    final SecretKeySpec key =
        new SecretKeySpec("YellowSubmarine".getBytes(StandardCharsets.US_ASCII), "Generic");
    final Mac nativeMac = Mac.getInstance(algorithm, NATIVE_PROVIDER);
    final Mac jceMac = Mac.getInstance(algorithm, "SunJCE");
    nativeMac.init(key);
    jceMac.init(key);
    for (int x = 0; x < 41; x++) {
      nativeMac.update(msg);
      jceMac.update(msg);
    }
    assertArrayEquals(jceMac.doFinal(), nativeMac.doFinal());
  }

  @ParameterizedTest
  @MethodSource("supportedHmacs")
  public void largeChunkBufferMsgs(final String algorithm) throws Exception {
    final ByteBuffer msg = ByteBuffer.allocate(4096);
    for (int x = 0; x < msg.capacity(); x++) {
      msg.put((byte) x);
    }
    msg.flip();
    final SecretKeySpec key =
        new SecretKeySpec("YellowSubmarine".getBytes(StandardCharsets.US_ASCII), "Generic");
    final Mac nativeMac = Mac.getInstance(algorithm, NATIVE_PROVIDER);
    final Mac jceMac = Mac.getInstance(algorithm, "SunJCE");
    nativeMac.init(key);
    jceMac.init(key);
    for (int x = 0; x < 41; x++) {
      nativeMac.update(msg.duplicate());
      jceMac.update(msg.duplicate());
    }
    assertArrayEquals(jceMac.doFinal(), nativeMac.doFinal());
  }

  @ParameterizedTest
  @MethodSource("supportedHmacs")
  public void largeChunkDirectBufferMsgs(final String algorithm) throws Exception {
    final ByteBuffer msg = ByteBuffer.allocateDirect(4096);
    for (int x = 0; x < msg.capacity(); x++) {
      msg.put((byte) x);
    }
    msg.flip();
    final SecretKeySpec key =
        new SecretKeySpec("YellowSubmarine".getBytes(StandardCharsets.US_ASCII), "Generic");
    final Mac nativeMac = Mac.getInstance(algorithm, NATIVE_PROVIDER);
    final Mac jceMac = Mac.getInstance(algorithm, "SunJCE");
    nativeMac.init(key);
    jceMac.init(key);
    for (int x = 0; x < 41; x++) {
      nativeMac.update(msg.duplicate());
      jceMac.update(msg.duplicate());
    }
    assertArrayEquals(jceMac.doFinal(), nativeMac.doFinal());
  }

  @Test
  public void cavpTestVectors() throws Throwable {
    final Map<String, String> macBySize = new HashMap<>();
    for (final String algorithm : SUPPORTED_HMACS) {
      macBySize.put(
          Integer.toString(Mac.getInstance(algorithm, NATIVE_PROVIDER).getMacLength()), algorithm);
    }

    // Now, test those from NIST CAVP
    final File rsp = new File(System.getProperty("test.data.dir"), "HMAC.rsp.gz");
    try (final InputStream is = new GZIPInputStream(new FileInputStream(rsp))) {
      final Iterator<RspTestEntry> iterator = RspTestEntry.iterateOverResource(is);
      while (iterator.hasNext()) {
        final RspTestEntry entry = iterator.next();
        // We don't support truncated hash tests so if Tlen doesn't
        // match L we skip this entry.
        if (!entry.getHeader("L").equals(entry.getInstance("Tlen"))) {
          continue;
        }
        final String algorithm = macBySize.get(entry.getHeader("L"));
        if (algorithm != null) {
          final Mac mac = Mac.getInstance(algorithm, NATIVE_PROVIDER);
          final SecretKey key =
              new SecretKeySpec(
                  Arrays.copyOf(
                      entry.getInstanceFromHex("Key"), Integer.parseInt(entry.getInstance("Klen"))),
                  algorithm);
          final byte[] message = entry.getInstanceFromHex("Msg");
          final byte[] expected = entry.getInstanceFromHex("Mac");
          testMac(mac, key, message, expected);
        }
      }
    }
  }

  @ParameterizedTest
  @MethodSource("supportedHmacs")
  public void largeKeys(final String algorithm) throws Throwable {
    // This tests keys large enough to require normalization
    final ByteBuffer msg = ByteBuffer.allocateDirect(4096);
    for (int x = 0; x < msg.capacity(); x++) {
      msg.put((byte) x);
    }
    msg.flip();
    final SecretKeySpec key = new SecretKeySpec(new byte[4096], "Generic");
    final Mac nativeMac = Mac.getInstance(algorithm, NATIVE_PROVIDER);
    final Mac jceMac = Mac.getInstance(algorithm, "SunJCE");
    nativeMac.init(key);
    jceMac.init(key);
    for (int x = 0; x < 41; x++) {
      nativeMac.update(msg.duplicate());
      jceMac.update(msg.duplicate());
    }
    assertArrayEquals(jceMac.doFinal(), nativeMac.doFinal());
  }

  @SuppressWarnings("serial")
  @ParameterizedTest
  @MethodSource("supportedHmacs")
  public void engineInitErrors(final String algorithm) throws Exception {
    final SecretKey validKey =
        new SecretKeySpec("yellowsubmarine".getBytes(StandardCharsets.UTF_8), "Generic");
    final PublicKey pubKey =
        new PublicKey() {
          @Override
          public String getFormat() {
            return "RAW";
          }

          @Override
          public byte[] getEncoded() {
            return "PublicKey".getBytes(StandardCharsets.UTF_8);
          }

          @Override
          public String getAlgorithm() {
            return "RAW";
          }
        };
    final SecretKey badFormat =
        new SecretKeySpec("yellowsubmarine".getBytes(StandardCharsets.UTF_8), "Generic") {
          @Override
          public String getFormat() {
            return "UnexpectedFormat";
          }
        };
    final SecretKey nullFormat =
        new SecretKeySpec("yellowsubmarine".getBytes(StandardCharsets.UTF_8), "Generic") {
          @Override
          public String getFormat() {
            return null;
          }
        };
    final SecretKey nullEncoding =
        new SecretKeySpec("yellowsubmarine".getBytes(StandardCharsets.UTF_8), "Generic") {
          @Override
          public byte[] getEncoded() {
            return null;
          }
        };

    final Mac mac = Mac.getInstance(algorithm, NATIVE_PROVIDER);

    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> mac.init(validKey, new IvParameterSpec(new byte[0])));
    assertThrows(InvalidKeyException.class, () -> mac.init(pubKey));
    assertThrows(InvalidKeyException.class, () -> mac.init(badFormat));
    assertThrows(InvalidKeyException.class, () -> mac.init(nullEncoding));

    TestUtil.assumeMinimumVersion("1.5.0", AmazonCorrettoCryptoProvider.INSTANCE);
    assertThrows(InvalidKeyException.class, () -> mac.init(nullFormat));
  }

  @ParameterizedTest
  @MethodSource("supportedHmacs")
  public void supportsCloneable(final String algorithm) throws Exception {
    TestUtil.assumeMinimumVersion("1.3.0", NATIVE_PROVIDER);
    final byte[] prefix = new byte[123]; // Arbitrary odd size
    for (int x = 0; x < prefix.length; x++) {
      prefix[x] = (byte) (x & 0xFF);
    }

    final byte[] suffix1 = new byte[prefix.length];
    final byte[] suffix2 = new byte[prefix.length];
    for (int x = 0; x < suffix1.length; x++) {
      // Just ensure these values are different from other patterns
      suffix1[x] = (byte) ((x & 0xFF) ^ 0x13);
      suffix2[x] = (byte) ((x & 0xFF) ^ 0xC7);
    }

    final SecretKeySpec key = new SecretKeySpec(new byte[4096], "Generic");
    final Mac mac = Mac.getInstance(algorithm, NATIVE_PROVIDER);

    mac.init(key);
    final byte[] prefixExpectedMac = mac.doFinal(prefix);
    mac.update(prefix);
    final byte[] msg1ExpectedMac = mac.doFinal(suffix1);
    mac.update(prefix);
    final byte[] msg2ExpectedMac = mac.doFinal(suffix2);

    mac.update(prefix, 0, prefix.length);
    final Mac prefixClone = (Mac) mac.clone();
    final Mac msg1Clone = (Mac) mac.clone();
    final Mac msg2Clone = (Mac) msg1Clone.clone();

    msg1Clone.update(suffix1);
    msg2Clone.update(suffix2);

    // Purposefully checking the prefix (shortest) one last
    assertArrayEquals(msg1ExpectedMac, msg1Clone.doFinal(), algorithm + " msg1");
    assertArrayEquals(msg2ExpectedMac, msg2Clone.doFinal(), algorithm + " msg2");
    assertArrayEquals(prefixExpectedMac, prefixClone.doFinal(), algorithm + " prefix");
  }

  @ParameterizedTest
  @MethodSource("supportedHmacs")
  public void supportsCloneableLarge(final String algorithm) throws Exception {
    TestUtil.assumeMinimumVersion("1.3.0", NATIVE_PROVIDER);
    final byte[] prefix = new byte[4096];
    final byte[] suffix1 = new byte[4096];
    final byte[] suffix2 = new byte[4096];

    for (int x = 0; x < prefix.length; x++) {
      prefix[x] = (byte) x;
      suffix1[x] = (byte) (x + 1);
      suffix2[x] = (byte) (x + 2);
    }

    final SecretKeySpec key = new SecretKeySpec(new byte[4096], "Generic");
    final Mac defaultInstance = Mac.getInstance(algorithm, "SunJCE");
    defaultInstance.init(key);
    defaultInstance.update(prefix);

    final byte[] expected1 = defaultInstance.doFinal(suffix1);

    defaultInstance.update(prefix);
    final byte[] expected2 = defaultInstance.doFinal(suffix2);

    final Mac original = Mac.getInstance(algorithm, NATIVE_PROVIDER);
    original.init(key);
    original.update(prefix);

    final Mac duplicate = (Mac) original.clone();

    original.update(suffix1);
    duplicate.update(suffix2);

    assertArraysHexEquals(expected1, original.doFinal());
    assertArraysHexEquals(expected2, duplicate.doFinal());
  }

  @ParameterizedTest
  @MethodSource("supportedHmacs")
  public void testDraggedState(final String algorithm) throws Exception {
    TestUtil.assumeMinimumVersion("1.3.0", NATIVE_PROVIDER);
    final byte[] prefix = new byte[4096];
    final byte[] suffix1 = new byte[4096];
    final byte[] suffix2 = new byte[4096];

    for (int x = 0; x < prefix.length; x++) {
      prefix[x] = (byte) x;
      suffix1[x] = (byte) (x + 1);
      suffix2[x] = (byte) (x + 2);
    }

    final SecretKeySpec key = new SecretKeySpec(new byte[4096], "Generic");
    final Mac defaultInstance = Mac.getInstance(algorithm, "SunJCE");
    defaultInstance.init(key);
    defaultInstance.update(prefix);
    final byte[] expected1 = defaultInstance.doFinal(suffix1);

    defaultInstance.update(prefix);
    final byte[] expected2 = defaultInstance.doFinal(suffix2);

    final Mac original = Mac.getInstance(algorithm, NATIVE_PROVIDER);
    final Mac duplicate = (Mac) original.clone();
    original.init(key);
    duplicate.init(key);

    // First use uses the explicitly cloned state
    original.update(prefix);
    duplicate.update(prefix);

    assertArraysHexEquals(expected1, original.doFinal(suffix1));
    assertArraysHexEquals(expected2, duplicate.doFinal(suffix2));

    // State has been reset and thus we might no longer be on the explicitly cloned state
    original.update(prefix);
    duplicate.update(prefix);

    assertArraysHexEquals(expected1, original.doFinal(suffix1));
    assertArraysHexEquals(expected2, duplicate.doFinal(suffix2));
  }

  @ParameterizedTest
  @MethodSource("supportedHmacs")
  public void selfTest(final String algorithm) throws Throwable {
    final String hashName = algorithm.substring(4);
    final Class<?> clazz = Class.forName(NATIVE_PROVIDER_PACKAGE + ".EvpHmac$" + hashName);
    assertEquals(
        SelfTestStatus.PASSED, ((SelfTestResult) sneakyInvoke(clazz, "runSelfTest")).getStatus());
  }
}
