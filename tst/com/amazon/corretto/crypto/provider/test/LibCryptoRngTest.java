// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyGetInternalClass;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyInvoke;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.amazon.corretto.crypto.provider.LibCryptoRng;
import com.amazon.corretto.crypto.provider.SelfTestResult;
import com.amazon.corretto.crypto.provider.SelfTestStatus;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class LibCryptoRngTest {
    private LibCryptoRng rnd;

    @BeforeEach
    public void setup() {
        rnd = new LibCryptoRng();
    }

    @AfterEach
    public void teardown() {
        rnd = null;
    }

    // A common mistake it when filling arrays to not do it properly and leave
    // zero gaps. To detect this, we'll generate arrays of different lengths
    // and check to see if certain bytes are always zero
    @Test
    public void testNextBytes() {
        for (int size = 0; size < 64; size++) {
            final byte[] checkArr = new byte[size];
            final byte[] arr = new byte[size];
            for (int trial = 0; trial < 4; trial++) {
                rnd.nextBytes(arr);
                System.out.println(Hex.encodeHex(arr));
                for (int x = 0; x < size; x++) {
                    checkArr[x] = (byte) (checkArr[x] | arr[x]);
                }
            }
            for (int x = 0; x < size; x++) {
                assertTrue(0 != checkArr[x],
                        "Check array size " + size + " position " + x + " is equal to zero");
            }
        }
    }

    // A common mistake it when filling arrays to not do it properly and leave
    // zero gaps. To detect this, we'll generate arrays of different lengths
    // and check to see if certain bytes are always zero
    @Test
    public void testGenerateSeed() {
        for (int size = 0; size < 64; size++) {
            final byte[] checkArr = new byte[size];
            for (int trial = 0; trial < 4; trial++) {
                final byte[] arr = rnd.generateSeed(size);
                System.out.println(Hex.encodeHex(arr));
                for (int x = 0; x < size; x++) {
                    checkArr[x] = (byte) (checkArr[x] | arr[x]);
                }
            }
            for (int x = 0; x < size; x++) {
                assertTrue(0 != checkArr[x],
                        "Check array size " + size + " position " + x + " is equal to zero");
            }
        }
    }

    // There really isn't a good way to test random numbers.
    // So we generate a few, ensure they aren't all the same
    // value and don't throw exceptions
    @Test
    public void testInt() {
        final int initial = rnd.nextInt();
        for (int trial = 0; trial < 10; trial++) {
            if (initial != rnd.nextInt()) {
                return;
            }
        }
        fail("Failed to find a different value");
    }

    @Test
    public void testLong() {
        final long initial = rnd.nextLong();
        for (int trial = 0; trial < 10; trial++) {
            if (initial != rnd.nextLong()) {
                return;
            }
        }
        fail("Failed to find a different value");
    }

    @Test
    public void reseed() {
        // Just ensure this doesn't crash
        rnd.setSeed(new byte[0]);
        rnd.setSeed(new byte[1]);
        rnd.setSeed(new byte[16]);
        rnd.setSeed(new byte[20]);
        rnd.setSeed(new byte[24]);
        rnd.setSeed(new byte[32]);
        rnd.setSeed(new byte[48]);
        rnd.setSeed(new byte[64]);
    }

    @Test
    public void largeRequest() {
        // prove we can request very large amounts of data, even if it requires
        // reseeding in the middle
        final byte[] bytes = new byte[12288];
        rnd.nextBytes(bytes);
        // Ensure that the resulting bytes haven't been left at zero
        // Probablistically, this will pass.
        byte[] tests = new byte[3];
        tests[0] = bytes[8192];
        tests[1] = bytes[8193];
        tests[2] = bytes[12287];
        rnd.nextBytes(bytes);
        assertTrue(tests[0] != bytes[8192]);
        assertTrue(tests[1] != bytes[8193]);
        assertTrue(tests[2] != bytes[12287]);
    }

    @Test
    public void selfTest() throws Throwable {
        Class<?> spi = sneakyGetInternalClass(LibCryptoRng.class, "SPI");
        SelfTestResult result = (SelfTestResult) sneakyInvoke(spi, "runSelfTest");
        assertEquals(SelfTestStatus.PASSED, result.getStatus());
    }

}
