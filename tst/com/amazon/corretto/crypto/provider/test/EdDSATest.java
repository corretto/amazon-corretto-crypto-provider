// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.NATIVE_PROVIDER;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Random;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledForJreRange;
import org.junit.jupiter.api.condition.JRE;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
@EnabledForJreRange(min = JRE.JAVA_15)
public class EdDSATest {

  private KeyPairGenerator nativeGen;
  private KeyPairGenerator jceGen;
  private KeyPairGenerator bcGen;
  private static final BouncyCastleProvider BOUNCYCASTLE_PROVIDER = new BouncyCastleProvider();

  @BeforeEach
  public void setup() throws GeneralSecurityException {
    nativeGen = KeyPairGenerator.getInstance("Ed25519", NATIVE_PROVIDER);
    jceGen = KeyPairGenerator.getInstance("Ed25519", "SunEC");
    bcGen = KeyPairGenerator.getInstance("Ed25519", BOUNCYCASTLE_PROVIDER);
  }

  @AfterEach
  public void teardown() {
    // It is unclear if JUnit always properly releases references to classes and thus we may have
    // memory leaks
    // if we do not properly null our references
    nativeGen = null;
    jceGen = null;
    bcGen = null;
  }

  @Test
  public void uniqueKeyGen() {
    final KeyPair kp1 = nativeGen.generateKeyPair();
    final KeyPair kp2 = nativeGen.generateKeyPair();

    final byte[] pk1 = kp1.getPrivate().getEncoded();
    final byte[] pk2 = kp2.getPrivate().getEncoded();

    final byte[] pbk1 = kp1.getPublic().getEncoded();
    final byte[] pbk2 = kp2.getPublic().getEncoded();

    assertFalse(Arrays.equals(pk1, pk2));
    assertFalse(Arrays.equals(pbk1, pbk2));
  }

  @Test
  public void keyGenValidation() throws GeneralSecurityException {
    // Generate Keys with ACCP & Sign/Verify with SunEC
    final byte[] message = new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    final KeyPair keyPair = nativeGen.generateKeyPair();

    final PKCS8EncodedKeySpec privateKeyPkcs8 =
        new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());
    final X509EncodedKeySpec publicKeyX509 =
        new X509EncodedKeySpec(keyPair.getPublic().getEncoded());

    final KeyFactory kf = KeyFactory.getInstance("EdDSA", "SunEC");

    final PrivateKey privateKey = kf.generatePrivate(privateKeyPkcs8);
    final PublicKey publicKey = kf.generatePublic(publicKeyX509);

    final Signature eddsa = Signature.getInstance("Ed25519", "SunEC");

    eddsa.initSign(privateKey);
    eddsa.update(message, 0, message.length);
    final byte[] signature = eddsa.sign();
    eddsa.initVerify(publicKey);
    eddsa.update(message);
    assertTrue(eddsa.verify(signature));
  }

  @Test
  public void keyFactoryValidation() throws GeneralSecurityException {
    assumeTrue(TestUtil.edKeyFactoryRegistered());
    final KeyPair keyPair = jceGen.generateKeyPair();

    final byte[] privateKeyJCE = keyPair.getPrivate().getEncoded();
    final byte[] publicKeyJCE = keyPair.getPublic().getEncoded();

    final PKCS8EncodedKeySpec privateKeyPkcs8 = new PKCS8EncodedKeySpec(privateKeyJCE);
    final X509EncodedKeySpec publicKeyX509 = new X509EncodedKeySpec(publicKeyJCE);

    final KeyFactory kf = KeyFactory.getInstance("Ed25519", NATIVE_PROVIDER);

    final byte[] privateKeyACCP = kf.generatePrivate(privateKeyPkcs8).getEncoded();
    final byte[] publicKeyACCP = kf.generatePublic(publicKeyX509).getEncoded();

    // Confirm that ACCP & SunEC keys are equivalent
    assertArrayEquals(privateKeyACCP, privateKeyJCE);
    assertArrayEquals(publicKeyACCP, publicKeyJCE);
  }

  @Test
  public void jceInteropValidation() throws GeneralSecurityException {
    // Generate keys with ACCP and use JCE KeyFactory to get equivalent JCE Keys
    final KeyPair keyPair = nativeGen.generateKeyPair();

    final PrivateKey privateKey = keyPair.getPrivate();
    final PublicKey publicKey = keyPair.getPublic();

    // Set up ACCP and JCE Signature Instances
    final Signature nativeSig = Signature.getInstance("Ed25519", NATIVE_PROVIDER);
    final Signature jceSig = Signature.getInstance("Ed25519", "SunEC");
    byte[] message, signatureACCP, signatureJCE;
    Random random = new Random();

    for (int messageLength = 1; messageLength <= 1024; messageLength++) {
      message = new byte[messageLength];
      random.nextBytes(message);
      // Sign with ACCP and verify with SunEC
      nativeSig.initSign(privateKey);
      nativeSig.update(message, 0, message.length);
      signatureACCP = nativeSig.sign();
      jceSig.initVerify(publicKey);
      jceSig.update(message);
      assertTrue(
          jceSig.verify(signatureACCP),
          "Native->JCE: Ed25519 (message length: " + messageLength + ")");

      // Sign with SunEC and verify with ACCP
      jceSig.initSign(privateKey);
      jceSig.update(message, 0, message.length);
      signatureJCE = jceSig.sign();
      nativeSig.initVerify(publicKey);
      nativeSig.update(message);
      assertTrue(
          nativeSig.verify(signatureJCE),
          "JCE->Native: Ed25519 (message length: " + messageLength + ")");

      assertArrayEquals(signatureJCE, signatureACCP);
    }
  }

  @Test
  public void bcInteropValidation() throws GeneralSecurityException {
    // Generate keys with ACCP and use BC KeyFactory to get equivalent Keys
    final Signature nativeSig = Signature.getInstance("Ed25519", NATIVE_PROVIDER);
    final Signature bcSig = Signature.getInstance("Ed25519", BOUNCYCASTLE_PROVIDER);
    final KeyPair keyPair = nativeGen.generateKeyPair();

    final PrivateKey privateKey = keyPair.getPrivate();
    final PublicKey publicKey = keyPair.getPublic();
    byte[] message, signatureACCP, signatureBC;
    Random random = new Random();

    for (int messageLength = 1; messageLength <= 1024; messageLength++) {
      message = new byte[messageLength];
      random.nextBytes(message);
      // Sign with ACCP, Verify with BouncyCastle
      nativeSig.initSign(privateKey);
      nativeSig.update(message, 0, message.length);
      signatureACCP = nativeSig.sign();
      bcSig.initVerify(publicKey);
      bcSig.update(message);
      assertTrue(bcSig.verify(signatureACCP), "Native->BC: Ed25519");

      // Sign with BouncyCastle, Verify with ACCP
      bcSig.initSign(privateKey);
      bcSig.update(message, 0, message.length);
      signatureBC = bcSig.sign();
      nativeSig.initVerify(publicKey);
      nativeSig.update(message);
      assertTrue(nativeSig.verify(signatureBC), "BC->Native: Ed25519");

      assertArrayEquals(signatureBC, signatureACCP);
    }
  }

  @Test
  public void bcKeyValidation() throws GeneralSecurityException {
    // Generate keys with ACCP and use BC KeyFactory to get equivalent Keys
    final KeyPair kp = nativeGen.generateKeyPair();
    final byte[] pkACCP = kp.getPrivate().getEncoded();
    final byte[] pbkACCP = kp.getPublic().getEncoded();

    final PKCS8EncodedKeySpec privateKeyPkcs8 = new PKCS8EncodedKeySpec(pkACCP);
    final X509EncodedKeySpec publicKeyX509 = new X509EncodedKeySpec(pbkACCP);

    final KeyFactory kf = KeyFactory.getInstance("Ed25519", BOUNCYCASTLE_PROVIDER);

    final byte[] pkBC = kf.generatePrivate(privateKeyPkcs8).getEncoded();
    final byte[] pbkBC = kf.generatePublic(publicKeyX509).getEncoded();

    // Confirm that ACCP & BC keys are equivalent
    assertArrayEquals(pkACCP, pkBC);
    assertArrayEquals(pbkACCP, pbkBC);
  }

  @Test
  public void jceKeyValidation() throws Exception {
    // Generate keys with ACCP and use JCE KeyFactory to get equivalent Keys
    final KeyPair kp = nativeGen.generateKeyPair();
    final Class<?> edPrivateKeyCls = Class.forName("java.security.interfaces.EdECPrivateKey");
    final Class<?> edPPublicKeyCls = Class.forName("java.security.interfaces.EdECPublicKey");
    assertTrue(edPrivateKeyCls.isAssignableFrom(kp.getPrivate().getClass()));
    assertTrue(edPPublicKeyCls.isAssignableFrom(kp.getPublic().getClass()));
    final byte[] privateKeyAccpEncoding = kp.getPrivate().getEncoded();
    final byte[] publicKeyAccpEncoding = kp.getPublic().getEncoded();

    final PKCS8EncodedKeySpec privateKeyPkcs8 = new PKCS8EncodedKeySpec(privateKeyAccpEncoding);
    final X509EncodedKeySpec publicKeyX509 = new X509EncodedKeySpec(publicKeyAccpEncoding);

    final KeyFactory kf = KeyFactory.getInstance("Ed25519", "SunEC");

    final PrivateKey privateKeyJce = kf.generatePrivate(privateKeyPkcs8);
    final PublicKey publicKeyJce = kf.generatePublic(publicKeyX509);

    // Confirm that ACCP & SunJCE keys are equivalent
    assertArrayEquals(privateKeyAccpEncoding, privateKeyJce.getEncoded());
    assertArrayEquals(publicKeyAccpEncoding, publicKeyJce.getEncoded());

    // SunEC keys produced by its KeyFactory should be usable by EdDSA from ACCP
    final Signature sigService = Signature.getInstance("EdDSA", NATIVE_PROVIDER);

    for (int messageLength = 1; messageLength <= 1024; messageLength++) {
      final byte[] message = new byte[messageLength];
      final Random rand = new Random(messageLength);
      rand.nextBytes(message);

      sigService.initSign(privateKeyJce);
      sigService.update(message);
      final byte[] signature = sigService.sign();

      sigService.initVerify(publicKeyJce);
      sigService.update(message);
      assertTrue(sigService.verify(signature));
    }
  }

  @Test
  public void eddsaValidation() throws GeneralSecurityException {
    // Generate keys, sign, & verify with ACCP
    final byte[] message = new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    final Signature eddsa = Signature.getInstance("Ed25519", NATIVE_PROVIDER);
    final KeyPair keyPair = nativeGen.generateKeyPair();

    eddsa.initSign(keyPair.getPrivate());
    eddsa.update(message, 0, message.length);
    final byte[] signature = eddsa.sign();

    eddsa.initVerify(keyPair.getPublic());
    eddsa.update(message, 0, message.length);
    assertTrue(eddsa.verify(signature));
  }

  @Test
  public void mismatchSignature() throws GeneralSecurityException {
    final byte[] message1 = new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    final byte[] message2 = new byte[] {5, 5, 5, 5, 5, 5, 5, 5, 5, 5};

    final KeyPair kp = nativeGen.generateKeyPair();

    final Signature nativeSig = Signature.getInstance("Ed25519", NATIVE_PROVIDER);
    final Signature jceSig = Signature.getInstance("Ed25519", "SunEC");

    nativeSig.initSign(kp.getPrivate());
    nativeSig.update(message1, 0, message1.length);
    final byte[] signature = nativeSig.sign();

    nativeSig.initVerify(kp.getPublic());
    nativeSig.update(message2, 0, message2.length);
    assertFalse(nativeSig.verify(signature));

    jceSig.initVerify(kp.getPublic());
    jceSig.update(message2, 0, message2.length);
    assertFalse(jceSig.verify(signature));
  }

  @Test
  public void testInvalidKey() throws GeneralSecurityException {
    assumeTrue(TestUtil.edKeyFactoryRegistered());
    byte[] invalidKeyBytes = new byte[] {};
    PKCS8EncodedKeySpec invalidPrivateKeySpec = new PKCS8EncodedKeySpec(invalidKeyBytes);
    X509EncodedKeySpec invalidPublicKeySpec = new X509EncodedKeySpec(invalidKeyBytes);

    final KeyFactory kf = KeyFactory.getInstance("Ed25519", NATIVE_PROVIDER);

    TestUtil.assertThrows(
        InvalidKeySpecException.class, () -> kf.generatePrivate(invalidPrivateKeySpec));
    TestUtil.assertThrows(
        InvalidKeySpecException.class, () -> kf.generatePublic(invalidPublicKeySpec));
  }

  @Test
  public void testNullInputs() throws GeneralSecurityException {
    // Test SunEC behavior
    KeyPair keyPair = jceGen.generateKeyPair();
    Signature jceSig = Signature.getInstance("Ed25519", "SunEC");
    // Test with null message
    jceSig.initSign(keyPair.getPrivate());
    TestUtil.assertThrows(NullPointerException.class, () -> jceSig.update((byte[]) null));
    // Test with null signature
    jceSig.initVerify(keyPair.getPublic());
    assertFalse(jceSig.verify(null));

    // Test BouncyCastle behavior
    KeyPair keyPair2 = bcGen.generateKeyPair();
    Signature bcSig = Signature.getInstance("Ed25519", BOUNCYCASTLE_PROVIDER);
    // Test with null message
    bcSig.initSign(keyPair2.getPrivate());
    TestUtil.assertThrows(NullPointerException.class, () -> bcSig.update((byte[]) null));
    // Test with null signature
    bcSig.initVerify(keyPair2.getPublic());
    TestUtil.assertThrows(NullPointerException.class, () -> bcSig.verify(null));

    // Test ACCP behavior
    KeyPair keyPair3 = nativeGen.generateKeyPair();
    Signature nativeSig = Signature.getInstance("Ed25519", NATIVE_PROVIDER);
    // Test with null message
    nativeSig.initSign(keyPair3.getPrivate());
    TestUtil.assertThrows(NullPointerException.class, () -> nativeSig.update((byte[]) null));
    // Test with null signature
    nativeSig.initVerify(keyPair3.getPublic());
    TestUtil.assertThrows(NullPointerException.class, () -> nativeSig.verify(null));
  }
}
