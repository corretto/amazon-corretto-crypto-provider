// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static org.junit.Assume.assumeTrue;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIf;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

@DisabledIf("com.amazon.corretto.crypto.provider.test.MLDSATest#isDisabled")
@Execution(ExecutionMode.CONCURRENT)
@ExtendWith(TestResultLogger.class)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class MLDSATest {
  private static final Provider NATIVE_PROVIDER = AmazonCorrettoCryptoProvider.INSTANCE;
  private static final int[] MESSAGE_LENGTHS = new int[] {0, 1, 16, 32, 2047, 2048, 2049, 4100};

  // TODO: remove this disablement when ACCP consumes an AWS-LC-FIPS release with ML-DSA
  public static boolean isDisabled() {
    return AmazonCorrettoCryptoProvider.INSTANCE.isFips()
        && !AmazonCorrettoCryptoProvider.INSTANCE.isExperimentalFips();
  }

  private static class TestParams {
    private final Provider signerProv;
    private final Provider verifierProv;
    private final PrivateKey priv;
    private final PublicKey pub;
    private final byte[] message;

    public TestParams(
        Provider signerProv,
        Provider verifierProv,
        PrivateKey priv,
        PublicKey pub,
        byte[] message) {
      this.signerProv = signerProv;
      this.verifierProv = verifierProv;
      this.priv = priv;
      this.pub = pub;
      this.message = message;
    }

    public String toString() {
      return String.format(
          "signer: %s, verifier: %s, message size: %d",
          signerProv.getName(), verifierProv.getName(), message.length);
    }
  }

  private static List<TestParams> getParams() throws Exception {
    List<TestParams> params = new ArrayList<TestParams>();
    for (String algo : new String[] {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"}) {
      for (int messageSize : MESSAGE_LENGTHS) {
        KeyPair keyPair = KeyPairGenerator.getInstance(algo, NATIVE_PROVIDER).generateKeyPair();
        PublicKey nativePub = keyPair.getPublic();
        PrivateKey nativePriv = keyPair.getPrivate();

        // Convert ACCP native key to BouncyCastle key, as BouncyCastle ML-DSA Signatures don't
        // support non-Bouncy-Castle keys.
        KeyFactory bcKf = KeyFactory.getInstance("ML-DSA", TestUtil.BC_PROVIDER);
        PublicKey bcPub = bcKf.generatePublic(new X509EncodedKeySpec(nativePub.getEncoded()));
        PrivateKey bcPriv = bcKf.generatePrivate(new PKCS8EncodedKeySpec(nativePriv.getEncoded()));

        Provider nativeProv = NATIVE_PROVIDER;
        Provider bcProv = TestUtil.BC_PROVIDER;

        byte[] message = new byte[messageSize];
        Arrays.fill(message, (byte) 'A');

        params.add(new TestParams(nativeProv, nativeProv, nativePriv, nativePub, message));
        params.add(new TestParams(nativeProv, bcProv, nativePriv, bcPub, message));
        params.add(new TestParams(bcProv, nativeProv, bcPriv, nativePub, message));
        params.add(new TestParams(bcProv, bcProv, bcPriv, bcPub, message));
      }
    }
    return params;
  }

  @ParameterizedTest
  @MethodSource("getParams")
  public void testInteropRoundTrips(TestParams params) throws Exception {
    Signature signer = Signature.getInstance("ML-DSA", params.signerProv);
    Signature verifier = Signature.getInstance("ML-DSA", params.verifierProv);
    PrivateKey priv = params.priv;
    PublicKey pub = params.pub;
    byte[] message = Arrays.copyOf(params.message, params.message.length);

    signer.initSign(priv);
    signer.update(message);
    byte[] signatureBytes = signer.sign();
    verifier.initVerify(pub);
    verifier.update(message);
    assertTrue(verifier.verify(signatureBytes));

    // Because ACCP's ML-DSA uses per-signature randomness, its signatures over identical inputs
    // should be unique.
    if (signer.getProvider() == NATIVE_PROVIDER) {
      signer.initSign(priv);
      signer.update(message);
      byte[] secondSignatureBytes = signer.sign();
      assertFalse(Arrays.equals(signatureBytes, secondSignatureBytes));
    }

    // Verifying a different message should result in verification failure
    if (message.length > 0) {
      signer.initSign(priv);
      signer.update(message);
      signatureBytes = signer.sign();
      verifier.initVerify(pub);
      byte[] otherMessage = Arrays.copyOf(message, message.length);
      otherMessage[0] ^= 0xff; // flip all bits in the first byte
      verifier.update(otherMessage);
      assertFalse(verifier.verify(signatureBytes));
    }

    // Corrupting the signature should result in verification failure
    signer.initSign(priv);
    signer.update(message);
    signatureBytes = signer.sign();
    verifier.initVerify(pub);
    verifier.update(message);
    signatureBytes[0] ^= 0xff; // flip all bits in the first byte
    assertFalse(verifier.verify(signatureBytes));
  }

  @ParameterizedTest
  @ValueSource(strings = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
  public void testKeyGeneration(String algo) throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algo, NATIVE_PROVIDER);
    KeyPair keyPair = keyGen.generateKeyPair();

    assertNotNull(keyPair);
    assertNotNull(keyPair.getPrivate());
    assertNotNull(keyPair.getPublic());
    assertEquals("ML-DSA", keyPair.getPrivate().getAlgorithm());
    assertEquals("ML-DSA", keyPair.getPublic().getAlgorithm());
  }

  @Test
  public void testKeyFactorySelfConversion() throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA", NATIVE_PROVIDER);
    KeyPair originalKeyPair = keyGen.generateKeyPair();

    KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA", NATIVE_PROVIDER);

    byte[] publicKeyEncoded = originalKeyPair.getPublic().getEncoded();
    PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyEncoded));
    assertArrayEquals(publicKeyEncoded, publicKey.getEncoded());

    byte[] privateKeyEncoded = originalKeyPair.getPrivate().getEncoded();
    PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyEncoded));
    assertArrayEquals(privateKeyEncoded, privateKey.getEncoded());
  }

  @Test
  public void testInvalidKeyInitialization() {
    assertThrows(
        InvalidKeyException.class,
        () -> {
          KeyPair rsaKeys = KeyPairGenerator.getInstance("RSA").generateKeyPair();
          Signature sig = Signature.getInstance("ML-DSA", NATIVE_PROVIDER);
          sig.initSign(rsaKeys.getPrivate());
        });

    assertThrows(
        InvalidKeyException.class,
        () -> {
          KeyPair rsaKeys = KeyPairGenerator.getInstance("RSA").generateKeyPair();
          Signature sig = Signature.getInstance("ML-DSA", NATIVE_PROVIDER);
          sig.initVerify(rsaKeys.getPublic());
        });
  }

  @Test
  public void documentBouncyCastleDifferences() throws Exception {
    // ACCP and BouncyCastle both encode ML-DSA public keys in "expanded "form and ML-DSA private
    // keys
    // in "seed" form
    KeyFactory bcKf = KeyFactory.getInstance("ML-DSA", TestUtil.BC_PROVIDER);
    KeyPair nativePair =
        KeyPairGenerator.getInstance("ML-DSA-44", NATIVE_PROVIDER).generateKeyPair();
    PublicKey nativePub = nativePair.getPublic();
    PrivateKey nativePriv = nativePair.getPrivate();
    PublicKey bcPub = bcKf.generatePublic(new X509EncodedKeySpec(nativePub.getEncoded()));
    PrivateKey bcPriv = bcKf.generatePrivate(new PKCS8EncodedKeySpec(nativePriv.getEncoded()));
    TestUtil.assertArraysHexEquals(bcPub.getEncoded(), nativePub.getEncoded());
    TestUtil.assertArraysHexEquals(bcPriv.getEncoded(), nativePriv.getEncoded());

    nativePair = KeyPairGenerator.getInstance("ML-DSA-65", NATIVE_PROVIDER).generateKeyPair();
    nativePub = nativePair.getPublic();
    nativePriv = nativePair.getPrivate();
    bcPub = bcKf.generatePublic(new X509EncodedKeySpec(nativePub.getEncoded()));
    bcPriv = bcKf.generatePrivate(new PKCS8EncodedKeySpec(nativePriv.getEncoded()));
    TestUtil.assertArraysHexEquals(bcPub.getEncoded(), nativePub.getEncoded());
    TestUtil.assertArraysHexEquals(bcPriv.getEncoded(), nativePriv.getEncoded());

    nativePair = KeyPairGenerator.getInstance("ML-DSA-87", NATIVE_PROVIDER).generateKeyPair();
    nativePub = nativePair.getPublic();
    nativePriv = nativePair.getPrivate();
    bcPub = bcKf.generatePublic(new X509EncodedKeySpec(nativePub.getEncoded()));
    bcPriv = bcKf.generatePrivate(new PKCS8EncodedKeySpec(nativePriv.getEncoded()));
    TestUtil.assertArraysHexEquals(bcPub.getEncoded(), nativePub.getEncoded());
    TestUtil.assertArraysHexEquals(bcPriv.getEncoded(), nativePriv.getEncoded());

    // TODO [childw] test keys that have been decoded from expanded form

    // BouncyCastle Signatures don't accept keys from other providers
    Signature bcSignature = Signature.getInstance("ML-DSA", TestUtil.BC_PROVIDER);
    final PrivateKey finalNativePriv = nativePriv;
    assertThrows(InvalidKeyException.class, () -> bcSignature.initSign(finalNativePriv));

    // However, ACCP can use BouncyCastle KeyPairs with seed-encoded  PrivateKeys
    Signature nativeSignature = Signature.getInstance("ML-DSA", NATIVE_PROVIDER);
    nativeSignature.initSign(bcPriv);
    byte[] sigBytes = nativeSignature.sign();
    nativeSignature.initVerify(bcPub);
    assertTrue(nativeSignature.verify(sigBytes));
  }

  @ParameterizedTest
  @MethodSource("getParams")
  public void testExtMu(TestParams params) throws Exception {
    // Only ACCP currently supports External Mu
    assumeTrue(params.signerProv == NATIVE_PROVIDER && params.verifierProv == NATIVE_PROVIDER);

    Signature signer = Signature.getInstance("ML-DSA", NATIVE_PROVIDER);
    Signature verifier = Signature.getInstance("ML-DSA", NATIVE_PROVIDER);
    Signature extMuSigner = Signature.getInstance("ML-DSA-ExtMu", NATIVE_PROVIDER);
    Signature extMuVerifier = Signature.getInstance("ML-DSA-ExtMu", NATIVE_PROVIDER);
    PrivateKey priv = params.priv;
    PublicKey pub = params.pub;

    byte[] message = Arrays.copyOf(params.message, params.message.length);
    byte[] mu = TestUtil.computeMLDSAMu(pub, message);
    assertEquals(64, mu.length);
    byte[] fakeMu = new byte[64];
    Arrays.fill(fakeMu, (byte) 0);

    // Test with "fake mu" -- contents don't matter if we're signing and verifying mu
    extMuSigner.initSign(priv);
    extMuSigner.update(fakeMu);
    byte[] signatureBytes = extMuSigner.sign();
    extMuVerifier.initVerify(pub);
    extMuVerifier.update(fakeMu);
    assertTrue(extMuVerifier.verify(signatureBytes));

    // Test with real mu
    extMuSigner.initSign(priv);
    extMuSigner.update(mu);
    signatureBytes = extMuSigner.sign();
    extMuVerifier.initVerify(pub);
    extMuVerifier.update(mu);
    assertTrue(extMuVerifier.verify(signatureBytes));

    // Sign mu, verify with message
    extMuSigner.initSign(priv);
    extMuSigner.update(mu);
    signatureBytes = extMuSigner.sign();
    verifier.initVerify(pub);
    verifier.update(message);
    assertTrue(verifier.verify(signatureBytes));

    // Sign message, verify with mu
    signer.initSign(priv);
    signer.update(message);
    signatureBytes = signer.sign();
    extMuVerifier.initVerify(pub);
    extMuVerifier.update(mu);
    assertTrue(extMuVerifier.verify(signatureBytes));

    // Tampering the signature induces failure
    extMuSigner.initSign(priv);
    extMuSigner.update(mu);
    signatureBytes = extMuSigner.sign();
    signatureBytes[0] ^= 0xff;
    extMuVerifier.initVerify(pub);
    extMuVerifier.update(mu);
    assertFalse(extMuVerifier.verify(signatureBytes));
  }

  @ParameterizedTest
  @ValueSource(strings = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
  public void testComputeMLDSAExtMu(String algorithm) throws Exception {
    KeyPair keyPair = KeyPairGenerator.getInstance(algorithm, NATIVE_PROVIDER).generateKeyPair();
    PublicKey nativePub = keyPair.getPublic();
    KeyFactory bcKf = KeyFactory.getInstance("ML-DSA", TestUtil.BC_PROVIDER);
    PublicKey bcPub = bcKf.generatePublic(new X509EncodedKeySpec(nativePub.getEncoded()));

    byte[] message = new byte[256];
    Arrays.fill(message, (byte) 0x41);
    byte[] mu = TestUtil.computeMLDSAMu(nativePub, message);
    assertEquals(64, mu.length);
    // We don't have any other implementations of mu calculation to test against, so just assert
    // that mu is equivalent
    // generated from both ACCP and BouncyCastle keys.
    assertArrayEquals(mu, TestUtil.computeMLDSAMu(bcPub, message));
  }
}
