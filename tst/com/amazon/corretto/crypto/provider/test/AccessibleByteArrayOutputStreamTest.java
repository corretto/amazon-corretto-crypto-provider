// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyConstruct;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyInvoke;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyInvoke_int;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
public class AccessibleByteArrayOutputStreamTest {

  @Test
  public void badConstructors() {
    assertThrows(IllegalArgumentException.class, () -> getInstance(-5, -5));
    assertThrows(IllegalArgumentException.class, () -> getInstance(-5, 10));
    assertThrows(IllegalArgumentException.class, () -> getInstance(20, 10));
  }

  @Test
  public void singleByteWrite() throws Throwable {
    OutputStream instance = getInstance(0, 5);
    instance.write(0);
    instance.write(1);
    instance.write(2);
    assertEquals(3, sneakyInvoke_int(instance, "size"));
    byte[] buf = sneakyInvoke(instance, "getDataBuffer");
    assertEquals(0, buf[0]);
    assertEquals(1, buf[1]);
    assertEquals(2, buf[2]);
  }

  @Test
  public void limitEnforced() throws Throwable {
    OutputStream instance = getInstance(0, 5);
    instance.write(new byte[4]);
    instance.write(5);
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          instance.write(6);
        });
  }

  @Test
  public void intMaxOverflow() throws Throwable {
    OutputStream instance = getInstance();
    instance.write(new byte[1024]);
    assertThrows(
        IllegalArgumentException.class, () -> instance.write(null, 0, Integer.MAX_VALUE - 512));
  }

  private void assertNewCapacity(
      OutputStream instance, int currentCapacity, int minimumNewCapacity, int expectedNewCapacity)
      throws Throwable {
    int actualNewCapacity =
        sneakyInvoke(instance, "calculateNewCapacity", currentCapacity, minimumNewCapacity, false);
    assertEquals(expectedNewCapacity, actualNewCapacity);
  }

  @Test
  public void bufferGrowthResizeToIntMax() throws Throwable {
    OutputStream instance = getInstance();

    /* If we have a buffer of 32 bytes, and we need 1 more byte, we should resize to 64 bytes */
    assertNewCapacity(instance, 32, 32 + 1, 64);

    /* Ensure other buffer sizes have the same pattern of doubling the current capacity. */
    assertNewCapacity(instance, 33, 33 + 1, 66);
    assertNewCapacity(instance, 100, 100 + 1, 200);
    assertNewCapacity(instance, 200, 200 + 1, 400);
    assertNewCapacity(instance, 400, 400 + 1, 800);

    /* Ensure resizing capacities between INT_MAX/2 and INT_MAX are clamped to INT_MAX */
    assertNewCapacity(
        instance, (Integer.MAX_VALUE / 2), (Integer.MAX_VALUE / 2) + 1, Integer.MAX_VALUE);
    assertNewCapacity(
        instance,
        (int) (Integer.MAX_VALUE * 0.75),
        (int) (Integer.MAX_VALUE * 0.75) + 1,
        Integer.MAX_VALUE);
    assertNewCapacity(instance, Integer.MAX_VALUE - 10, Integer.MAX_VALUE - 9, Integer.MAX_VALUE);
    assertNewCapacity(instance, Integer.MAX_VALUE - 2, Integer.MAX_VALUE - 1, Integer.MAX_VALUE);
    assertNewCapacity(instance, Integer.MAX_VALUE - 1, Integer.MAX_VALUE, Integer.MAX_VALUE);
  }

  @Test
  public void resetWorks() throws Throwable {
    OutputStream instance = getInstance(2, 5);
    byte[] expected = new byte[5];
    Arrays.fill(expected, (byte) 5);
    instance.write(expected);
    assertArrayEquals(expected, sneakyInvoke(instance, "getDataBuffer"));
    sneakyInvoke(instance, "reset");
    assertEquals(0, ((byte[]) sneakyInvoke(instance, "getDataBuffer"))[0]);
    instance.write(expected);
    assertArrayEquals(expected, sneakyInvoke(instance, "getDataBuffer"));
  }

  @Test
  public void writeByteBuffer() throws Throwable {
    OutputStream instance = getInstance(2, 10);
    byte[] expected = new byte[5];
    Arrays.fill(expected, (byte) 5);
    ByteBuffer wrapped = ByteBuffer.wrap(expected);
    ByteBuffer direct = ByteBuffer.allocateDirect(5);
    direct.put(expected).flip();

    sneakyInvoke(instance, "write", wrapped);
    sneakyInvoke(instance, "write", direct);

    assertEquals(wrapped.limit(), wrapped.position());
    assertEquals(direct.limit(), direct.position());
    expected = new byte[10];
    Arrays.fill(expected, (byte) 5);
    assertArrayEquals(expected, sneakyInvoke(instance, "getDataBuffer"));
  }

  @Test
  public void testClone() throws Throwable {
    OutputStream instance = getInstance(2, 5);
    byte[] expected = new byte[5];
    Arrays.fill(expected, (byte) 5);
    byte[] expected2 = new byte[5];
    Arrays.fill(expected2, (byte) 6);

    instance.write(expected);
    assertArrayEquals(expected, sneakyInvoke(instance, "getDataBuffer"));
    OutputStream cloned = sneakyInvoke(instance, "clone");
    assertArrayEquals(expected, sneakyInvoke(instance, "getDataBuffer"));
    sneakyInvoke(instance, "reset");
    assertArrayEquals(expected, sneakyInvoke(cloned, "getDataBuffer"));
    instance.write(expected2);
    assertArrayEquals(expected2, sneakyInvoke(instance, "getDataBuffer"));
    assertArrayEquals(expected, sneakyInvoke(cloned, "getDataBuffer"));
  }

  @Test
  public void testFinalWrite() throws Throwable {
    OutputStream instance = getInstance(0, Integer.MAX_VALUE);
    final byte[] data = {1, 2, 3, 4, 5, 6, 7};
    instance.write(data, 0, 3);
    assertEquals(3, sneakyInvoke_int(instance, "size"));
    byte[] buf1 = sneakyInvoke(instance, "getDataBuffer");
    assertEquals(1, buf1[0]);
    assertEquals(2, buf1[1]);
    assertEquals(3, buf1[2]);
    assertEquals(3, buf1.length);
    instance.write(data, 3, 2);
    assertEquals(5, sneakyInvoke_int(instance, "size"));
    byte[] buf2 = sneakyInvoke(instance, "getDataBuffer");
    assertNotEquals(buf1, buf2);
    assertEquals(6, buf2.length);
    sneakyInvoke(instance, "finalWrite", data, 5, 2);
    byte[] buf3 = sneakyInvoke(instance, "getDataBuffer");
    assertArrayEquals(data, buf3);
  }

  private static OutputStream getInstance(final Object... args) throws Throwable {
    return (OutputStream)
        sneakyConstruct(
            "com.amazon.corretto.crypto.provider.AccessibleByteArrayOutputStream", args);
  }
}
