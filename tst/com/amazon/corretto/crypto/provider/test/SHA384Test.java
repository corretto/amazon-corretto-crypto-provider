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

public class SHA384Test {

    private static final String SHA_384 = "SHA-384";

    @Before
    public void setUp() throws Exception {
        Security.addProvider(AmazonCorrettoCryptoProvider.INSTANCE);
    }

    private MessageDigest getDigest() throws Exception {
        return MessageDigest.getInstance(SHA_384, "AmazonCorrettoCryptoProvider");
    }

    @Test
    public void testNullDigest() throws Exception {
        MessageDigest digest = getDigest();
        assertArrayEquals(
            Hex.decodeHex("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b".toCharArray()),
            digest.digest()
        );
        digest = getDigest();
        digest.update(new byte[0]);
        assertArrayEquals(
            Hex.decodeHex("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b".toCharArray()),
            digest.digest()
        );
        digest = getDigest();
        digest.update(ByteBuffer.allocateDirect(0));
        assertArrayEquals(
            Hex.decodeHex("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b".toCharArray()),
            digest.digest()
        );
    }

    @Test
    public void testVector() throws Exception {
        MessageDigest digest = getDigest();
        digest.update("testing".getBytes());

        assertArrayEquals(
            Hex.decodeHex("cf4811d74fd40504674fc3273f824fa42f755b9660a2e902b57f1df74873db1a91a037bcee65f1a88ecd1ef57ff254c9".toCharArray()),
            digest.digest()
        );
    }

    @Test
    public void testFastPath() throws Exception {
        MessageDigest digest = getDigest();

        assertArrayEquals(
            Hex.decodeHex("cf4811d74fd40504674fc3273f824fa42f755b9660a2e902b57f1df74873db1a91a037bcee65f1a88ecd1ef57ff254c9".toCharArray()),
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
            Hex.decodeHex("cf4811d74fd40504674fc3273f824fa42f755b9660a2e902b57f1df74873db1a91a037bcee65f1a88ecd1ef57ff254c9".toCharArray()),
            digest.digest()
        );
    }

    @Test
    public void testRandomly() throws Exception {
        new HashFunctionTester(SHA_384).testRandomly(1000);
    }

    @Test
    public void testAPIDetails() throws Exception {
        new HashFunctionTester(SHA_384).testAPI();
    }

    @Test
    public void cavpShortVectors() throws Throwable {
        try (final InputStream is = new GZIPInputStream(TestUtil.getTestData("SHA384ShortMsg.rsp.gz"))) {
            new HashFunctionTester(SHA_384).test(RspTestEntry.iterateOverResource(is));
        }
    }
    
    @Test
    public void cavpLongVectors() throws Throwable {
        try (final InputStream is = new GZIPInputStream(TestUtil.getTestData("SHA384LongMsg.rsp.gz"))) {
            new HashFunctionTester(SHA_384).test(RspTestEntry.iterateOverResource(is));
        }
    }
}
