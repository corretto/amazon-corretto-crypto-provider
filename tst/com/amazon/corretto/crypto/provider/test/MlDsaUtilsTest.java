// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import com.amazon.corretto.crypto.provider.RuntimeCryptoException;
import com.amazon.corretto.crypto.utils.MlDsaUtils;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
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
public class MlDsaUtilsTest {
  private static final Provider NATIVE_PROVIDER = AmazonCorrettoCryptoProvider.INSTANCE;

  // TODO: remove this disablement when ACCP consumes an AWS-LC-FIPS release with ML-DSA
  private static boolean mlDsaDisabled() {
    return AmazonCorrettoCryptoProvider.INSTANCE.isFips()
        && !AmazonCorrettoCryptoProvider.INSTANCE.isExperimentalFips();
  }

  @ParameterizedTest
  @ValueSource(strings = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
  @DisabledIf("mlDsaDisabled")
  public void testComputeMu(String algorithm) throws Exception {
    KeyPair keyPair = KeyPairGenerator.getInstance(algorithm, NATIVE_PROVIDER).generateKeyPair();
    PublicKey nativePub = keyPair.getPublic();
    KeyFactory bcKf = KeyFactory.getInstance("ML-DSA", TestUtil.BC_PROVIDER);
    PublicKey bcPub = bcKf.generatePublic(new X509EncodedKeySpec(nativePub.getEncoded()));

    byte[] message = new byte[256];
    Arrays.fill(message, (byte) 0x41);
    byte[] mu = MlDsaUtils.computeMu(nativePub, message);
    assertEquals(64, mu.length);
    // We don't have any other implementations of mu calculation to test against, so just assert
    // that mu is equivalent generated from both ACCP and BouncyCastle keys.
    assertArrayEquals(mu, MlDsaUtils.computeMu(bcPub, message));
  }

  @Test
  @DisabledIf("mlDsaDisabled")
  public void testExpandPrivateKey() throws Exception {
    KeyFactory kf = KeyFactory.getInstance("ML-DSA", TestUtil.NATIVE_PROVIDER);

    // Parsing expanded keys discards the seed, so after expansion we're no longer dealing with
    // the seed. There are 24 bytes of PKCS8 overhead for each key. Raw private key sizes below.
    // https://openquantumsafe.org/liboqs/algorithms/sig/ml-dsa.html
    KeyPair nativePair =
        KeyPairGenerator.getInstance("ML-DSA-44", NATIVE_PROVIDER).generateKeyPair();
    assertEquals(54, nativePair.getPrivate().getEncoded().length);
    byte[] expanded = MlDsaUtils.expandPrivateKey(nativePair.getPrivate());
    assertEquals(2588, expanded.length);
    PrivateKey expandedPriv = kf.generatePrivate(new PKCS8EncodedKeySpec(expanded));
    assertEquals(2588, expandedPriv.getEncoded().length);

    nativePair = KeyPairGenerator.getInstance("ML-DSA-65", NATIVE_PROVIDER).generateKeyPair();
    assertEquals(54, nativePair.getPrivate().getEncoded().length);
    expanded = MlDsaUtils.expandPrivateKey(nativePair.getPrivate());
    assertEquals(4060, expanded.length);
    expandedPriv = kf.generatePrivate(new PKCS8EncodedKeySpec(expanded));
    assertEquals(4060, expandedPriv.getEncoded().length);

    nativePair = KeyPairGenerator.getInstance("ML-DSA-87", NATIVE_PROVIDER).generateKeyPair();
    assertEquals(54, nativePair.getPrivate().getEncoded().length);
    expanded = MlDsaUtils.expandPrivateKey(nativePair.getPrivate());
    assertEquals(4924, expanded.length);
    expandedPriv = kf.generatePrivate(new PKCS8EncodedKeySpec(expanded));
    assertEquals(4924, expandedPriv.getEncoded().length);

    // Lastly, do a sign/verify round trip with the expanded key
    nativePair = KeyPairGenerator.getInstance("ML-DSA-44", NATIVE_PROVIDER).generateKeyPair();
    expanded = MlDsaUtils.expandPrivateKey(nativePair.getPrivate());
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

  /**
   * Reports whatever algorithm and encoding a test needs, including the nulls the interface
   * permits. Implements both key interfaces so one instance drives both entry points.
   */
  private static final class TestKey implements PublicKey, PrivateKey {
    private static final long serialVersionUID = 1L;

    private final String algorithm;
    private final byte[] encoded;

    private TestKey(final String algorithm, final byte[] encoded) {
      this.algorithm = algorithm;
      this.encoded = encoded;
    }

    @Override
    public String getAlgorithm() {
      return algorithm;
    }

    @Override
    public String getFormat() {
      return null;
    }

    @Override
    public byte[] getEncoded() {
      return encoded;
    }
  }

  // A Key may return null from getEncoded() when it does not support encoding, as a key held in
  // hardware would, and getAlgorithm() is not specified to be non-null either. Both nulls must be
  // refused in Java: one reaches GetArrayLength(nullptr) in JNI, the other is dereferenced by the
  // algorithm check itself.
  //
  // Not gated on mlDsaDisabled(): every case is rejected before JNI, so this must also run in the
  // FIPS builds where computeMuInternal is not compiled at all.
  @Test
  public void testUnusableKeysAreRejected() {
    final TestKey unencodable = new TestKey("ML-DSA-44", null);
    final TestKey nullAlgorithm = new TestKey(null, new byte[32]);
    final TestKey wrongAlgorithm = new TestKey("RSA", new byte[32]);
    // Passes every key check, so it reaches the message check without reaching JNI.
    final TestKey encodable = new TestKey("ML-DSA-44", new byte[32]);

    final byte[] message = new byte[256];
    Arrays.fill(message, (byte) 0x41);

    TestUtil.assertThrows(
        IllegalArgumentException.class, () -> MlDsaUtils.computeMu(null, message));
    TestUtil.assertThrows(
        IllegalArgumentException.class, () -> MlDsaUtils.computeMu(unencodable, message));
    TestUtil.assertThrows(
        IllegalArgumentException.class, () -> MlDsaUtils.computeMu(nullAlgorithm, message));
    TestUtil.assertThrows(
        IllegalArgumentException.class, () -> MlDsaUtils.computeMu(wrongAlgorithm, message));
    TestUtil.assertThrows(
        IllegalArgumentException.class, () -> MlDsaUtils.computeMu(encodable, null));

    TestUtil.assertThrows(IllegalArgumentException.class, () -> MlDsaUtils.expandPrivateKey(null));
    TestUtil.assertThrows(
        IllegalArgumentException.class, () -> MlDsaUtils.expandPrivateKey(unencodable));
    TestUtil.assertThrows(
        IllegalArgumentException.class, () -> MlDsaUtils.expandPrivateKey(nullAlgorithm));
    TestUtil.assertThrows(
        IllegalArgumentException.class, () -> MlDsaUtils.expandPrivateKey(wrongAlgorithm));
  }

  // A key claiming ML-DSA whose encoding is a well-formed SPKI for another algorithm passes every
  // Java-side check, so only the parsed key's type tells the two apart. Unlike the cases above this
  // one does reach JNI, hence the mlDsaDisabled() gate.
  @Test
  @DisabledIf("mlDsaDisabled")
  public void testNonMlDsaSpkiIsRejected() throws Exception {
    final TestKey ecKeyClaimingMlDsa =
        new TestKey("ML-DSA-44", generateEcKeyPair().getPublic().getEncoded());

    final byte[] message = new byte[256];
    Arrays.fill(message, (byte) 0x41);

    TestUtil.assertThrows(
        IllegalArgumentException.class,
        "Not an ML-DSA public key",
        () -> MlDsaUtils.computeMu(ecKeyClaimingMlDsa, message));
  }

  // The private-key half of the same discrimination: a well-formed PKCS8 for another algorithm gets
  // past every Java-side check and is refused by der2EvpPrivateKey's EVP_PKEY_PQDSA check. The
  // exception type differs from computeMu's above, as the two javadocs document: this path reports
  // an unusable encoding as RuntimeCryptoException.
  @Test
  @DisabledIf("mlDsaDisabled")
  public void testNonMlDsaPkcs8IsRejected() throws Exception {
    final TestKey ecKeyClaimingMlDsa =
        new TestKey("ML-DSA-44", generateEcKeyPair().getPrivate().getEncoded());

    TestUtil.assertThrows(
        RuntimeCryptoException.class,
        "Unable to convert PKCS8_PRIV_KEY_INFO to EVP_PKEY",
        () -> MlDsaUtils.expandPrivateKey(ecKeyClaimingMlDsa));
  }

  private static KeyPair generateEcKeyPair() throws GeneralSecurityException {
    final KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
    ecGen.initialize(256);
    return ecGen.generateKeyPair();
  }
}
