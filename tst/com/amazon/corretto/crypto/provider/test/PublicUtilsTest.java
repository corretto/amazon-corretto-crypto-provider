// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import com.amazon.corretto.crypto.provider.PublicUtils;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIf;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@Execution(ExecutionMode.CONCURRENT)
@ExtendWith(TestResultLogger.class)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class PublicUtilsTest {
  private static final Provider NATIVE_PROVIDER = AmazonCorrettoCryptoProvider.INSTANCE;

  // TODO: remove this disablement when ACCP consumes an AWS-LC-FIPS release with ML-DSA
  private static boolean mlDsaDisabled() {
    return AmazonCorrettoCryptoProvider.INSTANCE.isFips()
        && !AmazonCorrettoCryptoProvider.INSTANCE.isExperimentalFips();
  }

  @ParameterizedTest
  @ValueSource(strings = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
  @DisabledIf("mlDsaDisabled")
  public void testComputeMLDSAExtMu(String algorithm) throws Exception {
    KeyPair keyPair = KeyPairGenerator.getInstance(algorithm, NATIVE_PROVIDER).generateKeyPair();
    PublicKey nativePub = keyPair.getPublic();
    KeyFactory bcKf = KeyFactory.getInstance("ML-DSA", TestUtil.BC_PROVIDER);
    PublicKey bcPub = bcKf.generatePublic(new X509EncodedKeySpec(nativePub.getEncoded()));

    byte[] message = new byte[256];
    Arrays.fill(message, (byte) 0x41);
    byte[] mu = PublicUtils.computeMLDSAMu(nativePub, message);
    assertEquals(64, mu.length);
    // We don't have any other implementations of mu calculation to test against, so just assert
    // that mu is equivalent generated from both ACCP and BouncyCastle keys.
    assertArrayEquals(mu, PublicUtils.computeMLDSAMu(bcPub, message));
  }

  @Test
  public void testExpandMLDSAKey() throws Exception {
    KeyFactory kf = KeyFactory.getInstance("ML-DSA", TestUtil.NATIVE_PROVIDER);

    // Parsing expanded keys discards the seed, so after expansion we're no longer dealing
    // with the seed. THere's ~24B of PKCS8 overhead for each key. Raw private key sizes below.
    // https://openquantumsafe.org/liboqs/algorithms/sig/ml-dsa.html
    KeyPair nativePair =
        KeyPairGenerator.getInstance("ML-DSA-44", NATIVE_PROVIDER).generateKeyPair();
    assertEquals(52, nativePair.getPrivate().getEncoded().length);
    byte[] expanded = PublicUtils.expandMLDSAKey(nativePair.getPrivate());
    assertEquals(2584, expanded.length);
    PrivateKey expandedPriv = kf.generatePrivate(new PKCS8EncodedKeySpec(expanded));
    assertEquals(2584, expandedPriv.getEncoded().length);

    nativePair = KeyPairGenerator.getInstance("ML-DSA-65", NATIVE_PROVIDER).generateKeyPair();
    assertEquals(52, nativePair.getPrivate().getEncoded().length);
    expanded = PublicUtils.expandMLDSAKey(nativePair.getPrivate());
    assertEquals(4056, expanded.length);
    expandedPriv = kf.generatePrivate(new PKCS8EncodedKeySpec(expanded));
    assertEquals(4056, expandedPriv.getEncoded().length);

    nativePair = KeyPairGenerator.getInstance("ML-DSA-87", NATIVE_PROVIDER).generateKeyPair();
    assertEquals(52, nativePair.getPrivate().getEncoded().length);
    expanded = PublicUtils.expandMLDSAKey(nativePair.getPrivate());
    assertEquals(4920, expanded.length);
    expandedPriv = kf.generatePrivate(new PKCS8EncodedKeySpec(expanded));
    assertEquals(4920, expandedPriv.getEncoded().length);

    // Lastly, do a sign/verify round trip with the expanded key
    nativePair =
            KeyPairGenerator.getInstance("ML-DSA-44", NATIVE_PROVIDER).generateKeyPair();
    expanded = PublicUtils.expandMLDSAKey(nativePair.getPrivate());
    expandedPriv = kf.generatePrivate(new PKCS8EncodedKeySpec(expanded));
    final byte[] message = new byte[256];
    Arrays.fill(message, (byte) 0x41);
    Signature signature = Signature.getInstance("ML-DSA", NATIVE_PROVIDER);
    signature.initSign(expandedPriv);
    signature.update(message);
    byte[] signatureBytes = signature.sign();
    signature.initVerify(nativePair.getPublic());
    signature.update(message);
    assertTrue(signature.verify(signatureBytes));
  }
}
