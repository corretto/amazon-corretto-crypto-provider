// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyInvoke;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

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

import com.amazon.corretto.crypto.provider.*;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;

public class HmacTest {
  private static final Class<?> UTILS_CLASS;
    private static final AmazonCorrettoCryptoProvider NATIVE_PROVIDER = AmazonCorrettoCryptoProvider.INSTANCE;
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

    @Test(expected = IllegalStateException.class)
    public void requireInitialization() throws GeneralSecurityException {
        final Mac hmac = Mac.getInstance("HmacSHA256", NATIVE_PROVIDER);
        hmac.update("This should fail".getBytes(StandardCharsets.US_ASCII));
    }

    // The algorithm on the key must be ignored for compatibility with existing JCE implementations
    // such as SUN and BouncyCastle
    public void wrongAlgorithmWorks() throws GeneralSecurityException {
        final Mac hmac = Mac.getInstance("HmacSHA256", NATIVE_PROVIDER);
        final SecretKeySpec key = new SecretKeySpec(
                "YellowSubmarine".getBytes(StandardCharsets.US_ASCII), "AES");
        hmac.init(key);
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void badParams() throws GeneralSecurityException {
        final Mac hmac = Mac.getInstance("HmacSHA256", NATIVE_PROVIDER);
        final SecretKeySpec key = new SecretKeySpec(
                "YellowSubmarine".getBytes(StandardCharsets.US_ASCII), "HmacSHA256");
        hmac.init(key, new IvParameterSpec(new byte[16]));
    }

    private void testMac(Mac mac, SecretKey key, byte[] message, byte[] expected) throws Throwable {
        sneakyInvoke(UTILS_CLASS, "testMac", mac, key, message, expected);
    }

    @Test
    public void knownValue() throws Throwable {
        try (final Scanner in = new Scanner(TestUtil.sneakyGetTestData("hmac.txt"), 
                                            StandardCharsets.US_ASCII.name())) {
            while (in.hasNext()) {
                final String type = in.next();
                SecretKey key = new SecretKeySpec(Hex.decodeHex(in.next().toCharArray()), "HMAC");
                byte[] message = Hex.decodeHex(in.next().toCharArray());
                switch (type) {
                    case "sha2":
                        testMac(Mac.getInstance("HmacSHA256", NATIVE_PROVIDER), key, message, Hex.decodeHex(in.next().toCharArray()));
                        testMac(Mac.getInstance("HmacSHA384", NATIVE_PROVIDER), key, message, Hex.decodeHex(in.next().toCharArray()));
                        testMac(Mac.getInstance("HmacSHA512", NATIVE_PROVIDER), key, message, Hex.decodeHex(in.next().toCharArray()));
                        break;
                    case "sha1":
                        testMac(Mac.getInstance("HmacSHA1", NATIVE_PROVIDER), key, message, Hex.decodeHex(in.next().toCharArray()));
                        break;
                    case "md5":
                        testMac(Mac.getInstance("HmacMD5", NATIVE_PROVIDER), key, message, Hex.decodeHex(in.next().toCharArray()));
                        break;
                    default:
                        throw new UnsupportedOperationException("Not yet built");
                }
            }
        }
    }

    @Test
    // Suppress redundant cast warnings; they're redundant in java 9 but not java 8
    @SuppressWarnings({"cast", "RedundantCast"})
    public void emptyHmac() throws Exception {
        final SecretKeySpec key = new SecretKeySpec(
                "YellowSubmarine".getBytes(StandardCharsets.US_ASCII), "Generic");
        for (final String algorithm : SUPPORTED_HMACS) {
            final Mac jceMac = Mac.getInstance(algorithm, "SunJCE");
            jceMac.init(key);
            final byte[] expected = jceMac.doFinal();

            Mac nativeMac = Mac.getInstance(algorithm, NATIVE_PROVIDER);
            nativeMac.init(key);
            assertArrayEquals(algorithm, expected, nativeMac.doFinal());

            nativeMac = Mac.getInstance(algorithm, NATIVE_PROVIDER);
            nativeMac.init(key);
            nativeMac.update(new byte[0]);
            assertArrayEquals(algorithm, expected, nativeMac.doFinal());

            nativeMac = Mac.getInstance(algorithm, NATIVE_PROVIDER);
            nativeMac.init(key);
            nativeMac.update((ByteBuffer) ByteBuffer.allocateDirect(4).limit(0));
            assertArrayEquals(algorithm, expected, nativeMac.doFinal());
        }
    }

    // These tests purposefully uses large enough data to bypass our internal buffering logic and force
    // multiple calls to the native layer.
    @Test
    public void largeArrayMsgs() throws Exception {
        final byte[] msg = new byte[256];
        for (int x = 0; x < msg.length; x++) {
            msg[x] = (byte) x;
        }
        final SecretKeySpec key = new SecretKeySpec(
                "YellowSubmarine".getBytes(StandardCharsets.US_ASCII), "Generic");
        for (final String algorithm : SUPPORTED_HMACS) {
            final Mac nativeMac = Mac.getInstance(algorithm, NATIVE_PROVIDER);
            final Mac jceMac = Mac.getInstance(algorithm, "SunJCE");
            nativeMac.init(key);
            jceMac.init(key);
            for (int x = 0; x < 41; x++) {
                nativeMac.update(msg);
                jceMac.update(msg);
            }
            assertArrayEquals(algorithm, jceMac.doFinal(), nativeMac.doFinal());
        }
    }

    @Test
    public void largeBufferMsgs() throws Exception {
        final ByteBuffer msg = ByteBuffer.allocate(256);
        for (int x = 0; x < msg.capacity(); x++) {
            msg.put((byte) x);
        }
        msg.flip();
        final SecretKeySpec key = new SecretKeySpec(
                "YellowSubmarine".getBytes(StandardCharsets.US_ASCII), "Generic");
        for (final String algorithm : SUPPORTED_HMACS) {
        final Mac nativeMac = Mac.getInstance(algorithm, NATIVE_PROVIDER);
            final Mac jceMac = Mac.getInstance(algorithm, "SunJCE");
            nativeMac.init(key);
            jceMac.init(key);
            for (int x = 0; x < 41; x++) {
                nativeMac.update(msg.duplicate());
                jceMac.update(msg.duplicate());
            }
            assertArrayEquals(algorithm, jceMac.doFinal(), nativeMac.doFinal());
        }
    }

    @Test
    public void largeDirectBufferMsgs() throws Exception {
        final ByteBuffer msg = ByteBuffer.allocateDirect(256);
        for (int x = 0; x < msg.capacity(); x++) {
            msg.put((byte) x);
        }
        msg.flip();
        final SecretKeySpec key = new SecretKeySpec(
                "YellowSubmarine".getBytes(StandardCharsets.US_ASCII), "Generic");
        for (final String algorithm : SUPPORTED_HMACS) {
            final Mac nativeMac = Mac.getInstance(algorithm, NATIVE_PROVIDER);
            final Mac jceMac = Mac.getInstance(algorithm, "SunJCE");
            nativeMac.init(key);
            jceMac.init(key);
            for (int x = 0; x < 41; x++) {
                nativeMac.update(msg.duplicate());
                jceMac.update(msg.duplicate());
            }
            assertArrayEquals(algorithm, jceMac.doFinal(), nativeMac.doFinal());
        }
    }

    @Test
    public void largeChunkArrayMsgs() throws Exception {
        final byte[] msg = new byte[4096];
        for (int x = 0; x < msg.length; x++) {
            msg[x] = (byte) x;
        }
        final SecretKeySpec key = new SecretKeySpec(
                "YellowSubmarine".getBytes(StandardCharsets.US_ASCII), "Generic");
        for (final String algorithm : SUPPORTED_HMACS) {
            final Mac nativeMac = Mac.getInstance(algorithm, NATIVE_PROVIDER);
            final Mac jceMac = Mac.getInstance(algorithm, "SunJCE");
            nativeMac.init(key);
            jceMac.init(key);
            for (int x = 0; x < 41; x++) {
                nativeMac.update(msg);
                jceMac.update(msg);
            }
            assertArrayEquals(algorithm, jceMac.doFinal(), nativeMac.doFinal());
        }
    }

    @Test
    public void largeChunkBufferMsgs() throws Exception {
        final ByteBuffer msg = ByteBuffer.allocate(4096);
        for (int x = 0; x < msg.capacity(); x++) {
            msg.put((byte) x);
        }
        msg.flip();
        final SecretKeySpec key = new SecretKeySpec(
                "YellowSubmarine".getBytes(StandardCharsets.US_ASCII), "Generic");
        for (final String algorithm : SUPPORTED_HMACS) {
            final Mac nativeMac = Mac.getInstance(algorithm, NATIVE_PROVIDER);
            final Mac jceMac = Mac.getInstance(algorithm, "SunJCE");
            nativeMac.init(key);
            jceMac.init(key);
            for (int x = 0; x < 41; x++) {
                nativeMac.update(msg.duplicate());
                jceMac.update(msg.duplicate());
            }
            assertArrayEquals(algorithm, jceMac.doFinal(), nativeMac.doFinal());
        }
    }

    @Test
    public void largeChunkDirectBufferMsgs() throws Exception {
        final ByteBuffer msg = ByteBuffer.allocateDirect(4096);
        for (int x = 0; x < msg.capacity(); x++) {
            msg.put((byte) x);
        }
        msg.flip();
        final SecretKeySpec key = new SecretKeySpec(
                "YellowSubmarine".getBytes(StandardCharsets.US_ASCII), "Generic");
        for (final String algorithm : SUPPORTED_HMACS) {
            final Mac nativeMac = Mac.getInstance(algorithm, NATIVE_PROVIDER);
            final Mac jceMac = Mac.getInstance(algorithm, "SunJCE");
            nativeMac.init(key);
            jceMac.init(key);
            for (int x = 0; x < 41; x++) {
                nativeMac.update(msg.duplicate());
                jceMac.update(msg.duplicate());
            }
            assertArrayEquals(algorithm, jceMac.doFinal(), nativeMac.doFinal());
        }
    }

    @Test
    public void cavpTestVectors() throws Throwable {
        final Map<String, String> macBySize = new HashMap<>();
        for (final String algorithm : SUPPORTED_HMACS) {
            macBySize.put(Integer.toString(Mac.getInstance(algorithm, NATIVE_PROVIDER).getMacLength()), algorithm);
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
                    final SecretKey key = new SecretKeySpec(
                            Arrays.copyOf(entry.getInstanceFromHex("Key"), Integer.parseInt(entry.getInstance("Klen"))),
                            algorithm);
                    final byte[] message = entry.getInstanceFromHex("Msg");
                    final byte[] expected = entry.getInstanceFromHex("Mac");
                    testMac(mac, key, message, expected);
                }
            }
        }
    }

    @Test
    public void largeKeys() throws Throwable {
        // This tests keys large enough to require normalization
        final ByteBuffer msg = ByteBuffer.allocateDirect(4096);
        for (int x = 0; x < msg.capacity(); x++) {
            msg.put((byte) x);
        }
        msg.flip();
        final SecretKeySpec key = new SecretKeySpec(new byte[4096], "Generic");
        for (final String algorithm : SUPPORTED_HMACS) {
            final Mac nativeMac = Mac.getInstance(algorithm, NATIVE_PROVIDER);
            final Mac jceMac = Mac.getInstance(algorithm, "SunJCE");
            nativeMac.init(key);
            jceMac.init(key);
            for (int x = 0; x < 41; x++) {
                nativeMac.update(msg.duplicate());
                jceMac.update(msg.duplicate());
            }
            assertArrayEquals(algorithm, jceMac.doFinal(), nativeMac.doFinal());
        }
    }

    @SuppressWarnings("serial")
    @Test
    public void engineInitErrors() throws Exception {
        final SecretKey validKey = new SecretKeySpec("yellowsubmarine".getBytes(StandardCharsets.UTF_8), "Generic");
        final PublicKey pubKey = new PublicKey() {
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
        final SecretKey badFormat = new SecretKeySpec("yellowsubmarine".getBytes(StandardCharsets.UTF_8), "Generic") {
            @Override
            public String getFormat() {
                return "UnexpectedFormat";
            }
        };
        final SecretKey nullEncoding = new SecretKeySpec("yellowsubmarine".getBytes(StandardCharsets.UTF_8), "Generic") {
            @Override
            public byte[] getEncoded() {
                return null;
            }
        };

        for (final String algorithm : SUPPORTED_HMACS) {
            final Mac mac = Mac.getInstance(algorithm, NATIVE_PROVIDER);

            assertThrows(InvalidAlgorithmParameterException.class, () -> mac.init(validKey, new IvParameterSpec(new byte[0])));
            assertThrows(InvalidKeyException.class, () -> mac.init(pubKey));
            assertThrows(InvalidKeyException.class, () -> mac.init(badFormat));
            assertThrows(InvalidKeyException.class, () -> mac.init(nullEncoding));
        }
    }

    @Test
    public void supportsCloneable() throws Exception {
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
        for (final String algorithm : SUPPORTED_HMACS) {
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
            assertArrayEquals(algorithm + " msg1", msg1ExpectedMac, msg1Clone.doFinal());
            assertArrayEquals(algorithm + " msg2", msg2ExpectedMac, msg2Clone.doFinal());
            assertArrayEquals(algorithm + " prefix", prefixExpectedMac, prefixClone.doFinal());
        }
    }

    @Test
    public void selfTest() {
        assertEquals(SelfTestStatus.PASSED, HmacSHA512Spi.runSelfTest().getStatus());
        assertEquals(SelfTestStatus.PASSED, HmacSHA384Spi.runSelfTest().getStatus());
        assertEquals(SelfTestStatus.PASSED, HmacSHA256Spi.runSelfTest().getStatus());
        assertEquals(SelfTestStatus.PASSED, HmacSHA1Spi.runSelfTest().getStatus());
        assertEquals(SelfTestStatus.PASSED, HmacMD5Spi.runSelfTest().getStatus());
    }
}
