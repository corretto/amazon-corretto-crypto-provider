// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import static java.lang.String.format;
import static com.amazon.corretto.crypto.provider.test.TestUtil.assumeMinimumVersion;
import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyConstruct;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import com.amazon.corretto.crypto.provider.InputBuffer;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class InputBufferTest {
    private static final AmazonCorrettoCryptoProvider PROVIDER = AmazonCorrettoCryptoProvider.INSTANCE; // used for version checks

    @SuppressWarnings("unchecked")
    private <T, S> InputBuffer<T, S> getBuffer(int capacity) {
      try {
          return (InputBuffer<T, S>) sneakyConstruct(InputBuffer.class.getName(), capacity);
      } catch (final Throwable ex) {
          throw new AssertionError(ex);
      }
    }

    @Test
    public void requiresPositiveCapacity() throws Throwable {
        assertThrows(IllegalArgumentException.class, () -> sneakyConstruct(InputBuffer.class.getName(), Integer.valueOf(-1)));
        assumeMinimumVersion("1.1.1", AmazonCorrettoCryptoProvider.INSTANCE);
        assertThrows(IllegalArgumentException.class, () -> sneakyConstruct(InputBuffer.class.getName(), Integer.valueOf(0)));
    }

    @Test
    public void minimalCase() {
        // Just tests the bare minimum configuration and ensures things are properly buffered
        byte[] expected = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        final ByteBuffer result = ByteBuffer.allocate(17);

        final InputBuffer<byte[], ByteBuffer> buffer = getBuffer(4);
        buffer.withInitialStateSupplier(() -> { return result; })
              .withUpdater((ctx, src, offset, length) -> ctx.put(src, offset, length))
              .withDoFinal(ByteBuffer::array);

        assertEquals(0, result.position(), "Initial state");
        buffer.update(expected, 0, 1);
        assertEquals(0, result.position(), "Buffering first chunk");
        buffer.update(expected, 1, 3);
        assertEquals(0, result.position(), "Buffering first chunk");
        
        buffer.update(expected, 4, 4);
        assertEquals(4, result.position(), "Buffering second chunk");

        buffer.update(ByteBuffer.wrap(expected, 8, 3));
        assertEquals(8, result.position(), "Buffering third chunk");

        ByteBuffer direct = ByteBuffer.allocateDirect(5);
        direct.put(expected, 11, 5);
        direct.flip();
        buffer.update(direct);
        assertEquals(16, result.position(), "All but last byte written");
        
        direct.position(2);
        direct.put(expected[16]);
        direct.limit(3);
        direct.position(2);
        buffer.update(direct);
        assertEquals(16, result.position(), "Prior to doFinal");
        assertArrayEquals(expected, buffer.doFinal());
    }

    @Test
    public void singleByteUpdates() {
        assumeMinimumVersion("1.1.1", AmazonCorrettoCryptoProvider.INSTANCE);
        byte[] expected = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        final ByteBuffer result = ByteBuffer.allocate(2);
        // In all cases, the byte being processed should be exactly one byte and one byte behind.

        final InputBuffer<byte[], ByteBuffer> buffer = getBuffer(1);
        buffer.withInitialStateSupplier(() -> { return result; })
              .withUpdater((ctx, src, offset, length) -> ctx.put(src, offset, length))
              .withDoFinal(ByteBuffer::array);

        for (int x = 0; x < expected.length; x++) {
            buffer.update(expected[x]);
            if (x == 0) {
                assertEquals(0, result.position(), "First byte buffered");
            } else {
                assertEquals(1, result.position(), format("Position %d flushed buffer", x));
                result.flip();
                assertEquals(expected[x - 1], result.get(), format("Position %d flushed correct value", x));
                result.clear();
            }
        }

        buffer.doFinal();
        assertEquals(1, result.position(), "doFinal flushed buffer");
        result.flip();
        assertEquals(expected[expected.length - 1], result.get(), "doFinal flushed correct value");
        result.clear();
    }

    @Test
    public void prefersSinglePass() {
        byte[] expected = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        // By leaving other handlers null, I'll force an exception if they are used
        final InputBuffer<byte[], Void> buffer = getBuffer(64);
        buffer.withSinglePass(Arrays::copyOfRange);

        buffer.update(expected, 0, 1);
        buffer.update(expected, 1, 3);
        buffer.update(expected, 4, 4);
        buffer.update(ByteBuffer.wrap(expected, 8, 3));
        ByteBuffer direct = ByteBuffer.allocateDirect(5);
        direct.put(expected, 11, 5);
        direct.flip();
        buffer.update(direct);
        direct.position(2);
        direct.put(expected[16]);
        direct.limit(3);
        direct.position(2);
        buffer.update(direct);
        assertArrayEquals(expected, buffer.doFinal());
    }

    @Test
    // Suppress redundant cast warnings; they're redundant in java 9 but not java 8
    @SuppressWarnings({"cast", "RedundantCast"})
    public void prefersBufferHandlers() {
        byte[] expected = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        final ByteBuffer result = ByteBuffer.allocate(17);
        final ByteBuffer direct = ByteBuffer.allocateDirect(17);
        direct.put(expected).flip();
        
        // By leaving other handlers null, I'll force an exception if they are used
        final InputBuffer<byte[], ByteBuffer> buffer = getBuffer(1);
        buffer.withInitialStateSupplier(() -> { return result;} )
              .withUpdater((ctx, src) -> ctx.put(src))
              .withDoFinal(ByteBuffer::array);
        
        buffer.update((ByteBuffer) direct.limit(2));
        assertEquals(direct.position(), result.position());
        buffer.update((ByteBuffer) direct.limit(4));
        assertEquals(direct.position(), result.position());
        buffer.update((ByteBuffer) direct.limit(8));
        assertEquals(direct.position(), result.position());
        buffer.update((ByteBuffer) direct.limit(11));
        assertEquals(direct.position(), result.position());
        buffer.update((ByteBuffer) direct.limit(15));
        assertEquals(direct.position(), result.position());
        buffer.update((ByteBuffer) direct.limit(17));
        assertEquals(direct.position(), result.position());
        assertArrayEquals(expected, buffer.doFinal());
    }

    @SuppressWarnings("unchecked")
    @Test
    public void cloneDuplicatesBufferAndState() throws Throwable {
        byte[] expected = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        final InputBuffer<byte[], ByteArrayOutputStream> buffer1 = getBuffer(16);
        buffer1.withInitialStateSupplier(ByteArrayOutputStream::new)
              .withUpdater((state, src, offset, length) -> { state.write(src, offset, length); })
              .withDoFinal(ByteArrayOutputStream::toByteArray)
              .withStateCloner((state) -> {
                    ByteArrayOutputStream cloned = new ByteArrayOutputStream();
                    try {
                        state.writeTo(cloned);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                    return cloned;
                });
        buffer1.update(expected, 0, expected.length);
        buffer1.update(expected, 0, expected.length);

        final InputBuffer<byte[], ByteArrayOutputStream> buffer2 =
                (InputBuffer<byte[], ByteArrayOutputStream>) TestUtil.sneakyInvoke(buffer1, "clone");
        buffer1.update(expected, 0, expected.length);
        buffer1.update(expected, 0, expected.length);

        byte[] buff1Result = buffer1.doFinal();
        assertEquals(expected.length * 4, buff1Result.length, "Buff 1 result length");
        int idx = 0;
        assertArrayEquals(expected, Arrays.copyOfRange(buff1Result, idx, idx + expected.length), "Buff 1 first quarter");
        idx += expected.length;
        assertArrayEquals(expected, Arrays.copyOfRange(buff1Result, idx, idx + expected.length), "Buff 1 second quarter");
        idx += expected.length;
        assertArrayEquals(expected, Arrays.copyOfRange(buff1Result, idx, idx + expected.length), "Buff 1 third quarter");
        idx += expected.length;
        assertArrayEquals( expected, Arrays.copyOfRange(buff1Result, idx, idx + expected.length), "Buff 1 forth quarter");

        byte[] buff2Result = buffer2.doFinal();
        idx = 0;
        assertEquals(expected.length * 2, buff2Result.length, "Buff 2 result length");
        assertArrayEquals(expected, Arrays.copyOfRange(buff2Result, idx, idx + expected.length), "Buff 2 first half");
        idx += expected.length;
        assertArrayEquals(expected, Arrays.copyOfRange(buff2Result, idx, idx + expected.length), "Buff 2 second half");
    }

    @Test
    public void cantCloneUncloneable() throws Throwable {
        final InputBuffer<byte[], byte[]> buffer = getBuffer(8);
        buffer.withInitialStateSupplier(() -> { return new byte[128]; } )
              .withUpdater((state, src, offset, length) -> { System.arraycopy(src, offset, state, 0, length); })
              .withDoFinal((state) -> state.clone());

        // Force initiation of state
        buffer.update(new byte[16], 0, 16);
        TestUtil.assertThrows(CloneNotSupportedException.class, () -> { TestUtil.sneakyInvoke(buffer, "clone"); } );
    }

    @Test
    public void nullStateProperlyHandled() throws Throwable {
      InputBuffer<byte[], byte[]> buffer = getBuffer(4);
      buffer.withInitialStateSupplier(() -> {
        return new byte[4];
      }).withUpdater((state, src, offset, length) -> {
        System.arraycopy(src, offset, state, 0, length);
      }).withDoFinal((state) -> new byte[] {state[0], state[1]});
      buffer.doFinal();
    }
}
