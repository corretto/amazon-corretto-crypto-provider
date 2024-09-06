// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.bcDigest;
import static com.amazon.corretto.crypto.provider.test.TestUtil.getEntriesFromFile;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.amazon.corretto.crypto.provider.CounterKdfSpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.stream.Stream;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.bouncycastle.crypto.generators.KDFCounterBytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KDFCounterParameters;
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
public class CounterKdfTest {
  @Test
  public void counterKdfsAreNotAvailableInFipsMode() {
    Stream.of("CounterKdfWithHmacSHA256", "CounterKdfWithHmacSHA384", "CounterKdfWithHmacSHA512")
        .forEach(
            alg -> {
              try {
                assertNotNull(SecretKeyFactory.getInstance(alg, TestUtil.NATIVE_PROVIDER));
                assertTrue(TestUtil.supportsExtraKdfs());
              } catch (final NoSuchAlgorithmException e) {
                assertFalse(TestUtil.supportsExtraKdfs());
              }
            });
  }

  @Test
  public void secretLengthCannotBeZero() {
    assertThrows(IllegalArgumentException.class, () -> new CounterKdfSpec(new byte[0], 1, "name"));
  }

  @Test
  public void outputLengthCannotBeZeroOrNegative() {
    assertThrows(IllegalArgumentException.class, () -> new CounterKdfSpec(new byte[1], 0, "name"));
    assertThrows(IllegalArgumentException.class, () -> new CounterKdfSpec(new byte[1], -1, "name"));
  }

  // The rest of the tests are only available in non-FIPS mode, or in experimental FIPS mode.
  @Test
  public void counterKdfExpectsCounterKdfSpecAsKeySpec() throws Exception {
    assumeTrue(TestUtil.supportsExtraKdfs());
    final SecretKeyFactory skf =
        SecretKeyFactory.getInstance("CounterKdfWithHmacSHA256", TestUtil.NATIVE_PROVIDER);
    assertThrows(
        InvalidKeySpecException.class, () -> skf.generateSecret(new PBEKeySpec(new char[4])));
  }

  @Test
  public void counterKdfWithEmptyInfoIsFine() throws Exception {
    assumeTrue(TestUtil.supportsExtraKdfs());
    final SecretKeyFactory skf =
        SecretKeyFactory.getInstance("CounterKdfWithHmacSHA256", TestUtil.NATIVE_PROVIDER);
    final CounterKdfSpec spec = new CounterKdfSpec(new byte[1], 10, "name");
    assertEquals(0, spec.getInfo().length);
    assertNotNull(skf.generateSecret(spec));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("counterKdfKatTests")
  public void counterKdfKatTests(final RspTestEntry entry) throws Exception {
    assumeTrue(TestUtil.supportsExtraKdfs());
    final String digest = jceDigestName(entry.getInstance("HASH"));
    assumeFalse("SHA1".equals(digest));
    final byte[] expected = entry.getInstanceFromHex("EXPECT");
    final byte[] secret = entry.getInstanceFromHex("SECRET");
    final byte[] info = entry.getInstanceFromHex("INFO");

    final CounterKdfSpec spec = new CounterKdfSpec(secret, info, expected.length, "SECRET_KEY");
    final String alg = "CounterKdfWithHmac" + digest;

    final SecretKeyFactory skf = SecretKeyFactory.getInstance(alg, TestUtil.NATIVE_PROVIDER);
    final byte[] actual = skf.generateSecret(spec).getEncoded();
    assertArrayEquals(expected, actual);
    // Checking that ACCP produces the same output as Bouncy Castle:
    assertArrayEquals(bcCounterKdf(digest, spec), actual);
  }

  private static String jceDigestName(final String digest) {
    if (digest.contains("-")) {
      return "SHA" + digest.substring(4);
    }
    return digest;
  }

  private static Stream<RspTestEntry> counterKdfKatTests() throws Exception {
    return getEntriesFromFile("kbkdf_counter.txt", false);
  }

  private static byte[] bcCounterKdf(final String digest, final CounterKdfSpec spec) {
    final byte[] result = new byte[spec.getOutputLen()];
    final KDFCounterParameters kdfParameters =
        new KDFCounterParameters(spec.getSecret(), spec.getInfo(), 32);
    final KDFCounterBytesGenerator kdf = new KDFCounterBytesGenerator(new HMac(bcDigest(digest)));
    kdf.init(kdfParameters);
    kdf.generateBytes(result, 0, result.length);
    return result;
  }
}
