// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.zip.GZIPInputStream;

import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.SAME_THREAD)
@ResourceLock(value = TestUtil.RESOURCE_REFLECTION)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ_WRITE)
public class SHA256Test {

    private static final String SHA_256 = "SHA-256";

    private MessageDigest getDigest() throws Exception {
        return MessageDigest.getInstance(SHA_256, TestUtil.NATIVE_PROVIDER);
    }

    @Test
    public void testNullDigest() throws Exception {
        MessageDigest digest = getDigest();
        assertArrayEquals(
            Hex.decodeHex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".toCharArray()),
            digest.digest()
        );
        digest = getDigest();
        digest.update(new byte[0]);
        assertArrayEquals(
            Hex.decodeHex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".toCharArray()),
            digest.digest()
        );
        digest = getDigest();
        digest.update(ByteBuffer.allocateDirect(0));
        assertArrayEquals(
            Hex.decodeHex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".toCharArray()),
            digest.digest()
        );
    }

    @Test
    public void testVector() throws Exception {
        MessageDigest digest = getDigest();
        digest.update("testing".getBytes());

        assertArrayEquals(
            Hex.decodeHex("cf80cd8aed482d5d1527d7dc72fceff84e6326592848447d2dc0b0e87dfc9a90".toCharArray()),
            digest.digest()
        );
    }

    @Test
    public void testFastPath() throws Exception {
        MessageDigest digest = getDigest();

        assertArrayEquals(
            Hex.decodeHex("cf80cd8aed482d5d1527d7dc72fceff84e6326592848447d2dc0b0e87dfc9a90".toCharArray()),
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
            Hex.decodeHex("cf80cd8aed482d5d1527d7dc72fceff84e6326592848447d2dc0b0e87dfc9a90".toCharArray()),
            digest.digest()
        );
    }

    @Test
    public void testRandomly() throws Exception {
        new HashFunctionTester(SHA_256).testRandomly(1000);
    }

    @Test
    public void testAPIDetails() throws Exception {
        new HashFunctionTester(SHA_256).testAPI();
    }
    
    @Test
    public void cavpShortVectors() throws Throwable {
        try (final InputStream is = new GZIPInputStream(TestUtil.getTestData("SHA256ShortMsg.rsp.gz"))) {
            new HashFunctionTester(SHA_256).test(RspTestEntry.iterateOverResource(is));
        }
    }
    
    @Test
    public void cavpLongVectors() throws Throwable {
        try (final InputStream is = new GZIPInputStream(TestUtil.getTestData("SHA256LongMsg.rsp.gz"))) {
            new HashFunctionTester(SHA_256).test(RspTestEntry.iterateOverResource(is));
        }
    }
}
