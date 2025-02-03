// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyInvoke;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import java.nio.ByteBuffer;
import org.junit.AssumptionViolatedException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class UtilsTest {
  private static final Class<?> UTILS_CLASS;

  static {
    try {
      UTILS_CLASS = Class.forName(TestUtil.NATIVE_PROVIDER_PACKAGE + ".Utils");
    } catch (final ClassNotFoundException ex) {
      throw new AssertionError(ex);
    }
  }

  boolean outputClobbers(ByteBuffer input, ByteBuffer output) throws Throwable {
    return (Boolean) sneakyInvoke(UTILS_CLASS, "outputClobbersInput", input, output);
  }

  private void assertOutputClobbers0(ByteBuffer input, ByteBuffer output) throws Throwable {
    assertTrue(outputClobbers(input, output));
  }

  private void assertOutputClobbers(ByteBuffer input, ByteBuffer output) throws Throwable {
    assertOutputClobbers0(input, output);
    assertOutputClobbers0(input.slice(), output);
    assertOutputClobbers0(input, output.slice());
    assertOutputClobbers0(input.slice(), output.slice());
  }

  private void assertNoClobber0(ByteBuffer input, ByteBuffer output) throws Throwable {
    assertFalse(outputClobbers(input, output));
  }

  private void assertNoClobber(ByteBuffer input, ByteBuffer output) throws Throwable {
    assertNoClobber0(input, output);
    assertNoClobber0(input.slice(), output);
    assertNoClobber0(input, output.slice());
    assertNoClobber0(input.slice(), output.slice());
  }

  boolean arraysClobber(byte[] input, int inputOffset, int length, byte[] output, int outputOffset)
      throws Throwable {
    return (Boolean)
        sneakyInvoke(
            UTILS_CLASS, "outputClobbersInput", input, inputOffset, length, output, outputOffset);
  }

  @BeforeAll
  public static void setUp() throws Exception {
    // Touch AmazonCorrettoCryptoProvider to get the JNI library loaded
    assertNotNull(AmazonCorrettoCryptoProvider.INSTANCE);
  }

  @Test
  public void whenArrayBuffersAreDifferentArrays_noClobber() throws Throwable {
    ByteBuffer a = ByteBuffer.allocate(100);
    ByteBuffer b = ByteBuffer.allocate(100);

    assertNoClobber(a, b);

    b.position(10);
    a.limit(11);

    assertNoClobber(a, b);
  }

  @Test
  public void whenArrayBuffersAreDifferentArrays_correctClobber() throws Throwable {
    ByteBuffer a = ByteBuffer.allocate(100);
    ByteBuffer b = a.duplicate();

    // Exact overlap
    assertNoClobber(a, b);
    b.limit(20);
    assertNoClobber(a, b);

    // Output clobbers
    b.position(10);
    assertOutputClobbers(a, b);
    a.limit(11);
    assertOutputClobbers(a, b);

    // Output leads, but is beyond the input limit
    a.limit(10);
    assertNoClobber(a, b);

    // Output lags
    b.position(1);
    a.position(2);
    assertNoClobber(a, b);
  }

  @Test
  public void whenOneBufferIsReadOnly_assumesClobber() throws Throwable {
    ByteBuffer a = ByteBuffer.allocate(100);
    ByteBuffer b = ByteBuffer.allocate(100).asReadOnlyBuffer();

    assertOutputClobbers(a, b);
  }

  @Test
  public void whenOneBufferIsDirect_noClobber() throws Throwable {
    ByteBuffer a = ByteBuffer.allocate(100);
    ByteBuffer b = ByteBuffer.allocateDirect(100);

    assertNoClobber(a, b);
    assertNoClobber(a.asReadOnlyBuffer(), b);
  }

  @Test
  public void whenBothBuffersAreDirect_fromDifferentAllocations_noClobber() throws Throwable {
    ByteBuffer a = ByteBuffer.allocateDirect(100);
    ByteBuffer b = ByteBuffer.allocateDirect(100);

    assertNoClobber(a, b);
  }

  @Test
  public void whenMaximumSizeNativeBuffersAreUsed_correctClobberDetermination() throws Throwable {
    ByteBuffer buf;
    try {
      buf = ByteBuffer.allocateDirect(Integer.MAX_VALUE);
    } catch (OutOfMemoryError e) {
      throw new AssumptionViolatedException("Unable to allocate 2GB native buffer", e);
    }

    ByteBuffer a = buf.duplicate();
    ByteBuffer b = buf.duplicate();

    b.position(b.limit() - 1);
    assertOutputClobbers(a, b);

    a.limit(1);
    assertNoClobber(a, b);

    a.limit(a.capacity());
    a.position(b.position());
    assertOutputClobbers(a, b);
  }

  @Test
  public void arraysClobberTests() throws Throwable {
    byte[] arr1 = new byte[10];
    byte[] arr2 = new byte[10];

    // Exact overlap
    assertFalse(arraysClobber(arr1, 0, 10, arr1, 0));
    // Different arrays
    assertFalse(arraysClobber(arr1, 0, 10, arr2, 0));
    // Same array, but clobbering
    assertTrue(arraysClobber(arr1, 0, 10, arr1, 5));
    assertTrue(arraysClobber(arr1, 0, 6, arr1, 5));
    assertTrue(arraysClobber(arr1, 1, 5, arr1, 5));
    // Same array, but outputs beyond input
    assertFalse(arraysClobber(arr1, 0, 5, arr1, 5));
    assertFalse(arraysClobber(arr1, 0, 5, arr1, 6));
    // Same array, but output lags
    assertFalse(arraysClobber(arr1, 5, 10, arr1, 0));
    assertFalse(arraysClobber(arr1, 5, 6, arr1, 0));
    assertFalse(arraysClobber(arr1, 5, 5, arr1, 0));
    assertFalse(arraysClobber(arr1, 5, 5, arr1, 1));
  }

  @Test
  public void getBooleanPropertyTests() throws Throwable {
    getBooleanPropertyTest("accp.property1", "true", true, true);
    getBooleanPropertyTest("accp.property2", "true", false, true);
    getBooleanPropertyTest("accp.property3", "False", true, false);
    getBooleanPropertyTest("accp.property4", "False", false, false);
    getBooleanPropertyTest("accp.property5", "dummy", true, true);
    getBooleanPropertyTest("accp.property6", "dummy", false, false);
  }

  private static void getBooleanPropertyTest(
      final String propertyName,
      final String value,
      final boolean defaultValue,
      final boolean expectedValue)
      throws Throwable {
    final String fullPropertyName = TestUtil.NATIVE_PROVIDER_PACKAGE + "." + propertyName;
    System.setProperty(fullPropertyName, value);
    assertEquals(
        expectedValue,
        ((Boolean) sneakyInvoke(UTILS_CLASS, "getBooleanProperty", propertyName, defaultValue))
            .booleanValue());
  }

  @Test
  public void getNativeContextReleaseStrategyPropertyTests() throws Throwable {
    getNativeContextReleaseStrategyPropertyTest("accp.native.property1", "HYBRID", "HYBRID");
    getNativeContextReleaseStrategyPropertyTest("accp.native.property2", "dummy", "HYBRID");
    getNativeContextReleaseStrategyPropertyTest("accp.native.property3", "LAZY", "LAZY");
    getNativeContextReleaseStrategyPropertyTest("accp.native.property4", "EAGER", "EAGER");
  }

  private static void getNativeContextReleaseStrategyPropertyTest(
      final String propertyName, final String value, final String expectedValue) throws Throwable {
    final String fullPropertyName = TestUtil.NATIVE_PROVIDER_PACKAGE + "." + propertyName;
    System.setProperty(fullPropertyName, value);
    assertEquals(
        expectedValue,
        (sneakyInvoke(UTILS_CLASS, "getNativeContextReleaseStrategyProperty", propertyName)
            .toString()));
  }

  @Test
  public void givenNull_whenCheckArrayLimits_expectException() {
    assertThrows(
        IllegalArgumentException.class,
        () -> sneakyInvoke(UTILS_CLASS, "checkArrayLimits", null, 0, 0));
  }

  @Test
  public void givenNegativeLengthOrNegativeOffset_whenCheckArrayLimits_expectException() {
    assertThrows(
        ArrayIndexOutOfBoundsException.class,
        () -> sneakyInvoke(UTILS_CLASS, "checkArrayLimits", new byte[10], -1, 0));
    assertThrows(
        ArrayIndexOutOfBoundsException.class,
        () -> sneakyInvoke(UTILS_CLASS, "checkArrayLimits", new byte[10], 0, -1));
  }

  @Test
  public void givenOutOfRangeLengthAndOffset_whenCheckArrayLimits_expectException() {
    assertThrows(
        ArrayIndexOutOfBoundsException.class,
        () -> sneakyInvoke(UTILS_CLASS, "checkArrayLimits", new byte[10], 5, 6));
  }

  @Test
  public void givenInRangeLengthAndOffset_whenCheckArrayLimits_expectNoException() {
    assertDoesNotThrow(() -> sneakyInvoke(UTILS_CLASS, "checkArrayLimits", new byte[10], 5, 5));
  }

  @Test
  public void givenNull_whenRequireNonNull_expectIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () -> sneakyInvoke(UTILS_CLASS, "requireNonNullString", (String) null, ""));
  }

  @Test
  public void givenNonNull_whenRequireNonNull_expectValue() throws Throwable {
    final String s = "TEST";
    assertEquals(s, sneakyInvoke(UTILS_CLASS, "requireNonNullString", s, ""));
  }
}
