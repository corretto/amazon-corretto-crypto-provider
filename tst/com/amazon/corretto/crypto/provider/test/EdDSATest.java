// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.NATIVE_PROVIDER;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.security.*;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
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

    final byte [] pk1 = kp1.getPrivate().getEncoded();
    final byte [] pk2 = kp2.getPrivate().getEncoded();

    final byte [] pbk1 = kp1.getPublic().getEncoded();
    final byte [] pbk2 = kp2.getPublic().getEncoded();

    assertTrue(!Arrays.equals(pk1, pk2));
    assertTrue(!Arrays.equals(pbk1, pbk2));
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
    final KeyPair keyPair = jceGen.generateKeyPair();

    final byte[] privateKeyJCE = keyPair.getPrivate().getEncoded();
    final byte[] publicKeyJCE = keyPair.getPublic().getEncoded();

    final PKCS8EncodedKeySpec privateKeyPkcs8 = new PKCS8EncodedKeySpec(privateKeyJCE);
    final X509EncodedKeySpec publicKeyX509 = new X509EncodedKeySpec(publicKeyJCE);

    final KeyFactory kf = KeyFactory.getInstance("Ed25519", NATIVE_PROVIDER);

    final byte[] privateKeyACCP = kf.generatePrivate(privateKeyPkcs8).getEncoded();
    final byte[] publicKeyACCP = kf.generatePublic(publicKeyX509).getEncoded();

    // Confirm that ACCP & SunEC keys are equivalent
    assertTrue(Arrays.equals(privateKeyACCP, privateKeyJCE));
    assertTrue(Arrays.equals(publicKeyACCP, publicKeyJCE));
  }

  @Test
  public void jceInteropValidation() throws GeneralSecurityException {
    // Generate keys with ACCP and use JCE KeyFactory to get equivalent JCE Keys
    final KeyPair keyPair = nativeGen.generateKeyPair();

    final PKCS8EncodedKeySpec privateKeyPkcs8 =
        new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());
    final X509EncodedKeySpec publicKeyX509 =
        new X509EncodedKeySpec(keyPair.getPublic().getEncoded());

    final KeyFactory kf = KeyFactory.getInstance("Ed25519", "SunEC");
    final PrivateKey privateKey = kf.generatePrivate(privateKeyPkcs8);
    final PublicKey publicKey = kf.generatePublic(publicKeyX509);

    // Set up ACCP and JCE Signature Instances
    final Signature nativeSig = Signature.getInstance("Ed25519", NATIVE_PROVIDER);
    final Signature jceSig = Signature.getInstance("Ed25519", "SunEC");

    // Sign with ACCP and verify with SunEC
    final byte[] message = new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    nativeSig.initSign(keyPair.getPrivate());
    nativeSig.update(message, 0, message.length);
    byte[] signature = nativeSig.sign();
    jceSig.initVerify(publicKey);
    jceSig.update(message);
    assertTrue(jceSig.verify(signature), "Native->JCE: Ed25519");

    // Sign with SunEC and verify with ACCP
    jceSig.initSign(privateKey);
    jceSig.update(message, 0, message.length);
    signature = jceSig.sign();
    nativeSig.initVerify(keyPair.getPublic());
    nativeSig.update(message);
    assertTrue(nativeSig.verify(signature), "JCE->Native: Ed25519");
  }

  @Test
  public void bcInteropValidation() throws GeneralSecurityException {
    // Generate keys with ACCP and use BC KeyFactory to get equivalent JCE Keys
    final byte[] message = new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    final Signature nativeSig = Signature.getInstance("Ed25519", NATIVE_PROVIDER);
    final Signature bcSig = Signature.getInstance("Ed25519", BOUNCYCASTLE_PROVIDER);
    final KeyPair keyPair = nativeGen.generateKeyPair();

    final PKCS8EncodedKeySpec privateKeyPkcs8 =
        new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());
    final X509EncodedKeySpec publicKeyX509 =
        new X509EncodedKeySpec(keyPair.getPublic().getEncoded());

    final KeyFactory kf = KeyFactory.getInstance("Ed25519", BOUNCYCASTLE_PROVIDER);

    final PrivateKey privateKey = kf.generatePrivate(privateKeyPkcs8);
    final PublicKey publicKey = kf.generatePublic(publicKeyX509);

    // Sign with ACCP, Verify with BouncyCastle
    nativeSig.initSign(keyPair.getPrivate());
    nativeSig.update(message, 0, message.length);
    byte[] signature = nativeSig.sign();
    bcSig.initVerify(publicKey);
    bcSig.update(message);
    assertTrue(bcSig.verify(signature), "Native->BC: Ed25519");

    bcSig.initSign(privateKey);
    bcSig.update(message, 0, message.length);
    signature = bcSig.sign();
    nativeSig.initVerify(keyPair.getPublic());
    nativeSig.update(message);
    assertTrue(nativeSig.verify(signature), "BC->Native: Ed25519");
  }

  @Test
  public void bcKeyValidation() throws GeneralSecurityException {
    // Generate keys with ACCP and use BC KeyFactory to get equivalent JCE Keys
    final KeyPair kp = nativeGen.generateKeyPair();
    final byte[] pkACCP = kp.getPrivate().getEncoded();
    final byte[] pbkACCP = kp.getPublic().getEncoded();

    final PKCS8EncodedKeySpec privateKeyPkcs8 = new PKCS8EncodedKeySpec(pkACCP);
    final X509EncodedKeySpec publicKeyX509 = new X509EncodedKeySpec(pbkACCP);

    final KeyFactory kf = KeyFactory.getInstance("Ed25519", BOUNCYCASTLE_PROVIDER);

    final byte[] pkBC = kf.generatePrivate(privateKeyPkcs8).getEncoded();
    final byte[] pbkBC = kf.generatePublic(publicKeyX509).getEncoded();

    // Confirm that ACCP & BC keys are equivalent
    assertTrue(Arrays.equals(pkACCP, pkBC));
    assertTrue(Arrays.equals(pbkACCP, pbkBC));
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
    final Signature eddsa = Signature.getInstance("Ed25519", NATIVE_PROVIDER);

    eddsa.initSign(kp.getPrivate());
    eddsa.update(message1, 0, message1.length);
    final byte[] signature = eddsa.sign();

    eddsa.initVerify(kp.getPublic());
    eddsa.update(message2, 0, message2.length);
    TestUtil.assertThrows(SignatureException.class, () -> eddsa.verify(signature));
  }

  @Test
  public void testInvalidKey() throws GeneralSecurityException {
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
    assertTrue(!jceSig.verify(null));

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
