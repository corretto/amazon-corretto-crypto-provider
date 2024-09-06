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

import com.amazon.corretto.crypto.provider.ConcatenationKdfSpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.stream.Stream;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.params.KDFParameters;
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
public class ConcatenationKdfTest {

  @Test
  public void concatenationKdfsAreNotAvailableInFipsMode() {
    Stream.of(
            "ConcatenationKdfWithSHA256",
            "ConcatenationKdfWithSHA384",
            "ConcatenationKdfWithSHA512",
            "ConcatenationKdfWithHmacSHA256",
            "ConcatenationKdfWithHmacSHA512")
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
    assertThrows(
        IllegalArgumentException.class, () -> new ConcatenationKdfSpec(new byte[0], 1, "name"));
  }

  @Test
  public void outputLengthCannotBeZeroOrNegative() {
    assertThrows(
        IllegalArgumentException.class, () -> new ConcatenationKdfSpec(new byte[10], 0, "name"));
    assertThrows(
        IllegalArgumentException.class, () -> new ConcatenationKdfSpec(new byte[10], -1, "name"));
  }

  // The rest of the tests are only available in non-FIPS mode, or in experimental FIPS mode.
  @Test
  public void concatenationKdfExpectsConcatenationKdfSpecAsKeySpec() throws Exception {
    assumeTrue(TestUtil.supportsExtraKdfs());
    final SecretKeyFactory skf =
        SecretKeyFactory.getInstance("ConcatenationKdfWithSha256", TestUtil.NATIVE_PROVIDER);
    assertThrows(
        InvalidKeySpecException.class, () -> skf.generateSecret(new PBEKeySpec(new char[4])));
  }

  @Test
  public void concatenationKdfWithEmptyInfoIsFine() throws Exception {
    assumeTrue(TestUtil.supportsExtraKdfs());
    final SecretKeyFactory skf =
        SecretKeyFactory.getInstance("ConcatenationKdfWithSha256", TestUtil.NATIVE_PROVIDER);
    final ConcatenationKdfSpec spec = new ConcatenationKdfSpec(new byte[1], 10, "name");
    assertEquals(0, spec.getInfo().length);
    assertNotNull(skf.generateSecret(spec));
  }

  @Test
  public void concatenationKdfHmacWithEmptySaltIsFine() throws Exception {
    assumeTrue(TestUtil.supportsExtraKdfs());
    final SecretKeyFactory skf =
        SecretKeyFactory.getInstance("ConcatenationKdfWithHmacSha256", TestUtil.NATIVE_PROVIDER);
    final ConcatenationKdfSpec spec1 = new ConcatenationKdfSpec(new byte[1], 10, "name");
    assertEquals(0, spec1.getInfo().length);
    assertEquals(0, spec1.getSalt().length);
    assertNotNull(skf.generateSecret(spec1));

    final ConcatenationKdfSpec spec2 =
        new ConcatenationKdfSpec(new byte[1], 10, "name", new byte[10]);
    assertEquals(10, spec2.getInfo().length);
    assertEquals(0, spec2.getSalt().length);
    assertNotNull(skf.generateSecret(spec2));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("sskdfKatTests")
  public void concatenationKdfKatTests(final RspTestEntry entry) throws Exception {
    assumeTrue(TestUtil.supportsExtraKdfs());
    final String digest = jceDigestName(entry.getInstance("HASH"));
    assumeFalse("SHA1".equals(digest) || "SHA224".equals(digest));
    final boolean digestPrf = entry.getInstance("VARIANT").equals("DIGEST");
    final byte[] expected = entry.getInstanceFromHex("EXPECT");
    final byte[] secret = entry.getInstanceFromHex("SECRET");
    final byte[] info = entry.getInstanceFromHex("INFO");

    final ConcatenationKdfSpec spec;
    if (entry.contains("SALT")) {
      spec =
          new ConcatenationKdfSpec(
              secret, expected.length, "SECRET_KEY", info, entry.getInstanceFromHex("SALT"));
    } else {
      spec = new ConcatenationKdfSpec(secret, expected.length, "SECRET_KEY", info);
    }

    final String alg = "ConcatenationKdfWith" + (digestPrf ? "" : "Hmac") + digest;

    final SecretKeyFactory skf = SecretKeyFactory.getInstance(alg, TestUtil.NATIVE_PROVIDER);
    final byte[] actual = skf.generateSecret(spec).getEncoded();
    assertArrayEquals(expected, actual);

    if (digestPrf) {
      // Bouncy Castle implements the digest variant. Here we check that ACCP is also producing the
      // same result as BC.
      assertArrayEquals(bcConcatenationKdf(digest, spec), actual);
    }
  }

  private static String jceDigestName(final String digest) {
    if (digest.contains("-")) {
      return "SHA" + digest.substring(4);
    }
    return digest;
  }

  private static Stream<RspTestEntry> sskdfKatTests() throws Exception {
    return getEntriesFromFile("sskdf.txt", false);
  }

  private static byte[] bcConcatenationKdf(final String digest, final ConcatenationKdfSpec spec) {
    final byte[] result = new byte[spec.getOutputLen()];
    final KDFParameters kdfParameters = new KDFParameters(spec.getSecret(), spec.getInfo());
    final ConcatenationKDFGenerator kdf = new ConcatenationKDFGenerator(bcDigest(digest));
    kdf.init(kdfParameters);
    kdf.generateBytes(result, 0, result.length);
    return result;
  }
}
