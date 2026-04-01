// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import com.amazon.corretto.crypto.utils.MlKemUtils;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIf;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Tests for MlKemUtils using Known Answer Tests from RFC 9935 Appendix C.1.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9935#appendix-C.1">RFC 9935 Appendix C.1</a>
 */
@Execution(ExecutionMode.CONCURRENT)
@ExtendWith(TestResultLogger.class)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class MlKemUtilsTest {
  private static final Provider NATIVE_PROVIDER = AmazonCorrettoCryptoProvider.INSTANCE;

  // RFC 9935 Appendix C.1 seed-format PKCS8 encodings.
  // The seed (d||z) is 000102...3e3f for all parameter sets; only the algorithm OID differs.
  private static final Map<String, String> SEED_PEM =
      Map.of(
          "ML-KEM-512",
              "MFQCAQAwCwYJYIZIAWUDBAQBBEKAQAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ"
                  + "GhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=",
          "ML-KEM-768",
              "MFQCAQAwCwYJYIZIAWUDBAQCBEKAQAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ"
                  + "GhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=",
          "ML-KEM-1024",
              "MFQCAQAwCwYJYIZIAWUDBAQDBEKAQAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ"
                  + "GhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=");

  // Expected expanded PKCS8 sizes: raw key + 28 bytes PKCS8 overhead
  private static final Map<String, Integer> EXPANDED_SIZE =
      Map.of("ML-KEM-512", 1660, "ML-KEM-768", 2428, "ML-KEM-1024", 3196);

  private static boolean mlKemDisabled() {
    try {
      KeyPairGenerator.getInstance("ML-KEM-512", NATIVE_PROVIDER);
      return false;
    } catch (Exception e) {
      return true;
    }
  }

  @ParameterizedTest
  @ValueSource(strings = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
  @DisabledIf("mlKemDisabled")
  public void testExpandSeedKey(String algorithm) throws Exception {
    KeyFactory kf = KeyFactory.getInstance("ML-KEM", NATIVE_PROVIDER);
    byte[] seedDer = Base64.getDecoder().decode(SEED_PEM.get(algorithm));

    PrivateKey seedKey = kf.generatePrivate(new PKCS8EncodedKeySpec(seedDer));
    byte[] expanded = MlKemUtils.expandPrivateKey(seedKey);

    assertEquals(EXPANDED_SIZE.get(algorithm).intValue(), expanded.length);

    // Expansion must be deterministic
    PrivateKey seedKey2 = kf.generatePrivate(new PKCS8EncodedKeySpec(seedDer));
    assertArrayEquals(expanded, MlKemUtils.expandPrivateKey(seedKey2));

    // Re-expanding an already-expanded key must be idempotent
    PrivateKey expandedKey = kf.generatePrivate(new PKCS8EncodedKeySpec(expanded));
    assertArrayEquals(expanded, MlKemUtils.expandPrivateKey(expandedKey));
  }

  @Test
  @DisabledIf("mlKemDisabled")
  public void testExpandPrivateKeyInvalidArgs() {
    TestUtil.assertThrows(IllegalArgumentException.class, () -> MlKemUtils.expandPrivateKey(null));
  }
}
