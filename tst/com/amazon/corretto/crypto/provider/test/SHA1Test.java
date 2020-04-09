// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.Security;
import java.util.zip.GZIPInputStream;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import org.apache.commons.codec.binary.Hex;
import org.junit.Before;
import org.junit.Test;

public class SHA1Test {

    private static final String ALGORITHM = "SHA-1";

    @Before
    public void setUp() throws Exception {
        Security.addProvider(AmazonCorrettoCryptoProvider.INSTANCE);
    }

    private MessageDigest getDigest() throws Exception {
        return MessageDigest.getInstance(ALGORITHM, "AmazonCorrettoCryptoProvider");
    }

    @Test
    public void testNullDigest() throws Exception {
        MessageDigest digest = getDigest();
        assertArrayEquals(
            Hex.decodeHex("da39a3ee5e6b4b0d3255bfef95601890afd80709".toCharArray()),
            digest.digest()
        );
        digest = getDigest();
        digest.update(new byte[0]);
        assertArrayEquals(
            Hex.decodeHex("da39a3ee5e6b4b0d3255bfef95601890afd80709".toCharArray()),
            digest.digest()
        );
        digest = getDigest();
        digest.update(ByteBuffer.allocateDirect(0));
        assertArrayEquals(
            Hex.decodeHex("da39a3ee5e6b4b0d3255bfef95601890afd80709".toCharArray()),
            digest.digest()
        );
    }

    @Test
    public void testVector() throws Exception {
        MessageDigest digest = getDigest();
        digest.update("testing".getBytes());

        assertArrayEquals(
            Hex.decodeHex("dc724af18fbdd4e59189f5fe768a5f8311527050".toCharArray()),
            digest.digest()
        );
    }

    @Test
    public void testFastPath() throws Exception {
        MessageDigest digest = getDigest();

        assertArrayEquals(
            Hex.decodeHex("dc724af18fbdd4e59189f5fe768a5f8311527050".toCharArray()),
            digest.digest("testing".getBytes())
        );
    }

    @Test
    public void testNativeByteBuffer() throws Exception {
        byte[] testData = "testing".getBytes();
        ByteBuffer nativeBuf = ByteBuffer.allocateDirect(testData.length);
        nativeBuf.put(testData);
        nativeBuf.flip();

        MessageDigest digest = getDigest();
        digest.update(nativeBuf);
        assertEquals(nativeBuf.position(), nativeBuf.limit());

        assertArrayEquals(
            Hex.decodeHex("dc724af18fbdd4e59189f5fe768a5f8311527050".toCharArray()),
            digest.digest()
        );
    }

    @Test
    public void testRandomly() throws Exception {
        new HashFunctionTester(ALGORITHM).testRandomly(1000);
    }

    @Test
    public void testAPIDetails() throws Exception {
        new HashFunctionTester(ALGORITHM).testAPI();
    }

    @Test
    public void cavpShortVectors() throws Throwable {
        try (final InputStream is = new GZIPInputStream(TestUtil.getTestData("SHA1ShortMsg.rsp.gz"))) {
            new HashFunctionTester(ALGORITHM).test(RspTestEntry.iterateOverResource(is));
        }
    }
    
    @Test
    public void cavpLongVectors() throws Throwable {
        try (final InputStream is = new GZIPInputStream(TestUtil.getTestData("SHA1LongMsg.rsp.gz"))) {
            new HashFunctionTester(ALGORITHM).test(RspTestEntry.iterateOverResource(is));
        }
    }
}
