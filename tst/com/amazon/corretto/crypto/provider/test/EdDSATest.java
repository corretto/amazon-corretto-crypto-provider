// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.NATIVE_PROVIDER;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.security.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Random;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519phSigner;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
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

  // TODO: remove this disablement when ACCP consumes an AWS-LC-FIPS release with Ed25519ph
  public static boolean ed25519phIsEnabled() {
    return !NATIVE_PROVIDER.isFips() || NATIVE_PROVIDER.isExperimentalFips();
  }

  private Signature bcPrehashSig =
      new Signature("Ed25519ph") {
        private final Ed25519phSigner signer = new Ed25519phSigner(new byte[] {});

        @Override
        protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
          try {
            Ed25519PrivateKeyParameters privateKeyParams =
                (Ed25519PrivateKeyParameters) PrivateKeyFactory.createKey(privateKey.getEncoded());
            signer.init(true, privateKeyParams);
          } catch (IOException e) {
            throw new RuntimeException(e);
          }
        }

        @Override
        protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
          try {
            Ed25519PublicKeyParameters publicKeyParams =
                (Ed25519PublicKeyParameters) PublicKeyFactory.createKey(publicKey.getEncoded());
            signer.init(false, publicKeyParams);
          } catch (IOException e) {
            throw new RuntimeException(e);
          }
        }

        @Override
        protected void engineUpdate(byte b) throws SignatureException {
          engineUpdate(new byte[] {b}, 0, 1);
        }

        @Override
        protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
          signer.update(b, off, len);
        }

        @Override
        protected byte[] engineSign() throws SignatureException {
          return signer.generateSignature();
        }

        @Override
        protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
          return signer.verifySignature(sigBytes);
        }

        @Override
        protected void engineSetParameter(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {
          throw new UnsupportedOperationException();
        }

        @Override
        @Deprecated
        protected void engineSetParameter(String param, Object value)
            throws InvalidParameterException {
          throw new UnsupportedOperationException();
        }

        @Override
        @Deprecated
        protected Object engineGetParameter(String param) throws InvalidParameterException {
          throw new UnsupportedOperationException();
        }
      };

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
  public void selfValidation() throws GeneralSecurityException {
    final Signature nativeSignerSig = Signature.getInstance("Ed25519", NATIVE_PROVIDER);
    final Signature nativeVerifierSig = Signature.getInstance("Ed25519", NATIVE_PROVIDER);
    testInteropValidation(nativeSignerSig, nativeVerifierSig, false);
  }

  @Test
  public void jceInteropValidation() throws GeneralSecurityException {
    final Signature nativeSig = Signature.getInstance("Ed25519", NATIVE_PROVIDER);
    final Signature jceSig = Signature.getInstance("Ed25519", "SunEC");
    testInteropValidation(nativeSig, jceSig, false);
  }

  @Test
  public void bcInteropValidation() throws GeneralSecurityException {
    final Signature nativeSig = Signature.getInstance("Ed25519", NATIVE_PROVIDER);
    final Signature bcSig = Signature.getInstance("Ed25519", BOUNCYCASTLE_PROVIDER);
    testInteropValidation(nativeSig, bcSig, false);
  }

  @Test
  public void selfValidationPh() throws GeneralSecurityException {
    assumeTrue(ed25519phIsEnabled());
    final Signature nativeSignerSig = Signature.getInstance("Ed25519ph", NATIVE_PROVIDER);
    final Signature nativeVerifierSig = Signature.getInstance("Ed25519ph", NATIVE_PROVIDER);
    testInteropValidation(nativeSignerSig, nativeVerifierSig, true);
  }

  @Test
  public void jceInteropValidationPh() throws GeneralSecurityException {
    assumeTrue(ed25519phIsEnabled());
    final Signature nativeSig = Signature.getInstance("Ed25519ph", NATIVE_PROVIDER);
    final Signature jceSig = Signature.getInstance("Ed25519", "SunEC");
    makeJceSignaturePh(jceSig);
    testInteropValidation(nativeSig, jceSig, true);
  }

  @Test
  public void bcInteropValidationPh() throws GeneralSecurityException {
    assumeTrue(ed25519phIsEnabled());
    final Signature nativeSig = Signature.getInstance("Ed25519ph", NATIVE_PROVIDER);
    testInteropValidation(nativeSig, bcPrehashSig, true);
  }

  @Test // sanity check to assert that JCE and BC are interoperable
  public void bcJceInteropValidationPh() throws GeneralSecurityException {
    assumeTrue(ed25519phIsEnabled());
    final Signature jceSig = Signature.getInstance("Ed25519", "SunEC");
    makeJceSignaturePh(jceSig);
    testInteropValidation(jceSig, bcPrehashSig, true);
  }

  @Test // https://www.rfc-editor.org/rfc/rfc8032.html#section-7.3
  public void jceRfc8032KAT() throws Exception {
    // Generate keys with ACCP and use JCE KeyFactory to get equivalent Keys
    final Class<?> edPrivateKeyCls = Class.forName("java.security.interfaces.EdECPrivateKey");
    final Class<?> edPPublicKeyCls = Class.forName("java.security.interfaces.EdECPublicKey");

    byte[] pkcs8 = {
      (byte) 0x30,
      (byte) 0x2e,
      (byte) 0x02,
      (byte) 0x01,
      (byte) 0x00,
      (byte) 0x30,
      (byte) 0x05,
      (byte) 0x06,
      (byte) 0x03,
      (byte) 0x2b,
      (byte) 0x65,
      (byte) 0x70,
      (byte) 0x04,
      (byte) 0x22,
      (byte) 0x04,
      (byte) 0x20,
      (byte) 0x83,
      (byte) 0x3f,
      (byte) 0xe6,
      (byte) 0x24,
      (byte) 0x09,
      (byte) 0x23,
      (byte) 0x7b,
      (byte) 0x9d,
      (byte) 0x62,
      (byte) 0xec,
      (byte) 0x77,
      (byte) 0x58,
      (byte) 0x75,
      (byte) 0x20,
      (byte) 0x91,
      (byte) 0x1e,
      (byte) 0x9a,
      (byte) 0x75,
      (byte) 0x9c,
      (byte) 0xec,
      (byte) 0x1d,
      (byte) 0x19,
      (byte) 0x75,
      (byte) 0x5b,
      (byte) 0x7d,
      (byte) 0xa9,
      (byte) 0x01,
      (byte) 0xb9,
      (byte) 0x6d,
      (byte) 0xca,
      (byte) 0x3d,
      (byte) 0x42
    };
    byte[] x509 = {
      (byte) 0x30,
      (byte) 0x2a,
      (byte) 0x30,
      (byte) 0x05,
      (byte) 0x06,
      (byte) 0x03,
      (byte) 0x2b,
      (byte) 0x65,
      (byte) 0x70,
      (byte) 0x03,
      (byte) 0x21,
      (byte) 0x00,
      (byte) 0xec,
      (byte) 0x17,
      (byte) 0x2b,
      (byte) 0x93,
      (byte) 0xad,
      (byte) 0x5e,
      (byte) 0x56,
      (byte) 0x3b,
      (byte) 0xf4,
      (byte) 0x93,
      (byte) 0x2c,
      (byte) 0x70,
      (byte) 0xe1,
      (byte) 0x24,
      (byte) 0x50,
      (byte) 0x34,
      (byte) 0xc3,
      (byte) 0x54,
      (byte) 0x67,
      (byte) 0xef,
      (byte) 0x2e,
      (byte) 0xfd,
      (byte) 0x4d,
      (byte) 0x64,
      (byte) 0xeb,
      (byte) 0xf8,
      (byte) 0x19,
      (byte) 0x68,
      (byte) 0x34,
      (byte) 0x67,
      (byte) 0xe2,
      (byte) 0xbf
    };

    final PKCS8EncodedKeySpec privateKeyPkcs8 = new PKCS8EncodedKeySpec(pkcs8);
    final X509EncodedKeySpec publicKeyX509 = new X509EncodedKeySpec(x509);
    final KeyFactory kf = KeyFactory.getInstance("Ed25519", "SunEC");
    final PrivateKey privateKey = kf.generatePrivate(privateKeyPkcs8);
    final PublicKey publicKey = kf.generatePublic(publicKeyX509);

    Signature signer = Signature.getInstance("Ed25519", "SunEC");
    makeJceSignaturePh(signer);
    Signature verifier = Signature.getInstance("Ed25519", "SunEC");
    makeJceSignaturePh(verifier);

    // NOTE: JDK takes _the message itself_, not a hash...
    byte[] message = new byte[] {0x61, 0x62, 0x63};
    signer.initSign(privateKey);
    signer.update(message);
    byte[] signature = signer.sign();
    verifier.initVerify(publicKey);
    verifier.update(message);
    assertTrue(verifier.verify(signature), String.format("JCE->JCE: Ed25519ph"));

    byte[] expected = {
      (byte) 0x98,
      (byte) 0xa7,
      (byte) 0x02,
      (byte) 0x22,
      (byte) 0xf0,
      (byte) 0xb8,
      (byte) 0x12,
      (byte) 0x1a,
      (byte) 0xa9,
      (byte) 0xd3,
      (byte) 0x0f,
      (byte) 0x81,
      (byte) 0x3d,
      (byte) 0x68,
      (byte) 0x3f,
      (byte) 0x80,
      (byte) 0x9e,
      (byte) 0x46,
      (byte) 0x2b,
      (byte) 0x46,
      (byte) 0x9c,
      (byte) 0x7f,
      (byte) 0xf8,
      (byte) 0x76,
      (byte) 0x39,
      (byte) 0x49,
      (byte) 0x9b,
      (byte) 0xb9,
      (byte) 0x4e,
      (byte) 0x6d,
      (byte) 0xae,
      (byte) 0x41,
      (byte) 0x31,
      (byte) 0xf8,
      (byte) 0x50,
      (byte) 0x42,
      (byte) 0x46,
      (byte) 0x3c,
      (byte) 0x2a,
      (byte) 0x35,
      (byte) 0x5a,
      (byte) 0x20,
      (byte) 0x03,
      (byte) 0xd0,
      (byte) 0x62,
      (byte) 0xad,
      (byte) 0xf5,
      (byte) 0xaa,
      (byte) 0xa1,
      (byte) 0x0b,
      (byte) 0x8c,
      (byte) 0x61,
      (byte) 0xe6,
      (byte) 0x36,
      (byte) 0x06,
      (byte) 0x2a,
      (byte) 0xaa,
      (byte) 0xd1,
      (byte) 0x1c,
      (byte) 0x2a,
      (byte) 0x26,
      (byte) 0x08,
      (byte) 0x34,
      (byte) 0x06
    };
    assertArrayEquals(expected, signature);
  }

  @Test // https://www.rfc-editor.org/rfc/rfc8032.html#section-7.3
  public void nativeRfc8032KAT() throws Exception {
    // Generate keys with ACCP and use JCE KeyFactory to get equivalent Keys
    final Class<?> edPrivateKeyCls = Class.forName("java.security.interfaces.EdECPrivateKey");
    final Class<?> edPPublicKeyCls = Class.forName("java.security.interfaces.EdECPublicKey");

    byte[] pkcs8 = {
      (byte) 0x30,
      (byte) 0x2e,
      (byte) 0x02,
      (byte) 0x01,
      (byte) 0x00,
      (byte) 0x30,
      (byte) 0x05,
      (byte) 0x06,
      (byte) 0x03,
      (byte) 0x2b,
      (byte) 0x65,
      (byte) 0x70,
      (byte) 0x04,
      (byte) 0x22,
      (byte) 0x04,
      (byte) 0x20,
      (byte) 0x83,
      (byte) 0x3f,
      (byte) 0xe6,
      (byte) 0x24,
      (byte) 0x09,
      (byte) 0x23,
      (byte) 0x7b,
      (byte) 0x9d,
      (byte) 0x62,
      (byte) 0xec,
      (byte) 0x77,
      (byte) 0x58,
      (byte) 0x75,
      (byte) 0x20,
      (byte) 0x91,
      (byte) 0x1e,
      (byte) 0x9a,
      (byte) 0x75,
      (byte) 0x9c,
      (byte) 0xec,
      (byte) 0x1d,
      (byte) 0x19,
      (byte) 0x75,
      (byte) 0x5b,
      (byte) 0x7d,
      (byte) 0xa9,
      (byte) 0x01,
      (byte) 0xb9,
      (byte) 0x6d,
      (byte) 0xca,
      (byte) 0x3d,
      (byte) 0x42
    };
    byte[] x509 = {
      (byte) 0x30,
      (byte) 0x2a,
      (byte) 0x30,
      (byte) 0x05,
      (byte) 0x06,
      (byte) 0x03,
      (byte) 0x2b,
      (byte) 0x65,
      (byte) 0x70,
      (byte) 0x03,
      (byte) 0x21,
      (byte) 0x00,
      (byte) 0xec,
      (byte) 0x17,
      (byte) 0x2b,
      (byte) 0x93,
      (byte) 0xad,
      (byte) 0x5e,
      (byte) 0x56,
      (byte) 0x3b,
      (byte) 0xf4,
      (byte) 0x93,
      (byte) 0x2c,
      (byte) 0x70,
      (byte) 0xe1,
      (byte) 0x24,
      (byte) 0x50,
      (byte) 0x34,
      (byte) 0xc3,
      (byte) 0x54,
      (byte) 0x67,
      (byte) 0xef,
      (byte) 0x2e,
      (byte) 0xfd,
      (byte) 0x4d,
      (byte) 0x64,
      (byte) 0xeb,
      (byte) 0xf8,
      (byte) 0x19,
      (byte) 0x68,
      (byte) 0x34,
      (byte) 0x67,
      (byte) 0xe2,
      (byte) 0xbf
    };

    final PKCS8EncodedKeySpec privateKeyPkcs8 = new PKCS8EncodedKeySpec(pkcs8);
    final X509EncodedKeySpec publicKeyX509 = new X509EncodedKeySpec(x509);
    final KeyFactory kf = KeyFactory.getInstance("Ed25519");
    final PrivateKey privateKey = kf.generatePrivate(privateKeyPkcs8);
    final PublicKey publicKey = kf.generatePublic(publicKeyX509);

    Signature signer = Signature.getInstance("Ed25519ph", NATIVE_PROVIDER);
    Signature verifier = Signature.getInstance("Ed25519ph", NATIVE_PROVIDER);

    // NOTE: ACCP takes a _hash of the message_ (for now), not the message itself...
    byte[] message = MessageDigest.getInstance("SHA-512").digest(new byte[] {0x61, 0x62, 0x63});
    signer.initSign(privateKey);
    signer.update(message);
    byte[] signature = signer.sign();
    verifier.initVerify(publicKey);
    verifier.update(message);
    assertTrue(verifier.verify(signature), String.format("ACCP->ACCP: Ed25519ph"));

    byte[] expected = {
      (byte) 0x98,
      (byte) 0xa7,
      (byte) 0x02,
      (byte) 0x22,
      (byte) 0xf0,
      (byte) 0xb8,
      (byte) 0x12,
      (byte) 0x1a,
      (byte) 0xa9,
      (byte) 0xd3,
      (byte) 0x0f,
      (byte) 0x81,
      (byte) 0x3d,
      (byte) 0x68,
      (byte) 0x3f,
      (byte) 0x80,
      (byte) 0x9e,
      (byte) 0x46,
      (byte) 0x2b,
      (byte) 0x46,
      (byte) 0x9c,
      (byte) 0x7f,
      (byte) 0xf8,
      (byte) 0x76,
      (byte) 0x39,
      (byte) 0x49,
      (byte) 0x9b,
      (byte) 0xb9,
      (byte) 0x4e,
      (byte) 0x6d,
      (byte) 0xae,
      (byte) 0x41,
      (byte) 0x31,
      (byte) 0xf8,
      (byte) 0x50,
      (byte) 0x42,
      (byte) 0x46,
      (byte) 0x3c,
      (byte) 0x2a,
      (byte) 0x35,
      (byte) 0x5a,
      (byte) 0x20,
      (byte) 0x03,
      (byte) 0xd0,
      (byte) 0x62,
      (byte) 0xad,
      (byte) 0xf5,
      (byte) 0xaa,
      (byte) 0xa1,
      (byte) 0x0b,
      (byte) 0x8c,
      (byte) 0x61,
      (byte) 0xe6,
      (byte) 0x36,
      (byte) 0x06,
      (byte) 0x2a,
      (byte) 0xaa,
      (byte) 0xd1,
      (byte) 0x1c,
      (byte) 0x2a,
      (byte) 0x26,
      (byte) 0x08,
      (byte) 0x34,
      (byte) 0x06
    };
    assertArrayEquals(expected, signature);
  }

  public void testInteropValidation(Signature signer, Signature verifier, boolean preHash)
      throws GeneralSecurityException {
    final String signerStr = signer.getProvider() == null ? "BC" : signer.getProvider().getName();
    final String verifierStr =
        verifier.getProvider() == null ? "BC" : verifier.getProvider().getName();
    // We're agnostic to key provider as demonstrated in other tests
    final KeyPair keyPair = nativeGen.generateKeyPair();

    PrivateKey privateKey = keyPair.getPrivate();
    final PublicKey publicKey = keyPair.getPublic();
    byte[] message, signature1, signature2;
    Random random = new Random();

    for (int messageLength = 1; messageLength <= 1024; messageLength++) {
      message = new byte[messageLength];
      random.nextBytes(message);
      if (preHash) {
        message = MessageDigest.getInstance("SHA-512").digest(message);
      }
      // Sign with signer, Verify with verifier
      signer.initSign(privateKey);
      signer.update(message);
      signature1 = signer.sign();
      verifier.initVerify(publicKey);
      verifier.update(message);
      assertTrue(
          verifier.verify(signature1),
          String.format("%s->%s: Ed25519%s", signerStr, verifierStr, preHash ? "ph" : ""));

      // Sign with verifier, Verify with signer
      verifier.initSign(privateKey);
      verifier.update(message);
      signature2 = verifier.sign();
      signer.initVerify(publicKey);
      signer.update(message);
      assertTrue(
          signer.verify(signature2),
          String.format("%s->%s: Ed25519%s", verifierStr, signerStr, preHash ? "ph" : ""));

      // Ed25519(ph) is deterministic, so signatures should be equal
      assertArrayEquals(signature1, signature2);
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
    final byte[] message = new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    testEdDSAValidation("EdDSA", message);
    testEdDSAValidation("Ed25519", message);
  }

  @Test
  public void ed25519phValidation() throws GeneralSecurityException {
    assumeTrue(ed25519phIsEnabled());
    final byte[] preHash =
        MessageDigest.getInstance("SHA-512").digest(new byte[10]); // message content is irrelevant
    testEdDSAValidation("Ed25519ph", preHash);
  }

  private void testEdDSAValidation(String algorithm, byte[] message)
      throws GeneralSecurityException {
    // Generate keys, sign, & verify with ACCP
    final Signature eddsa = Signature.getInstance(algorithm, NATIVE_PROVIDER);
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
    byte[] message1 = new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    byte[] message2 = new byte[] {5, 5, 5, 5, 5, 5, 5, 5, 5, 5};

    final KeyPair kp = nativeGen.generateKeyPair();

    Signature nativeSig = Signature.getInstance("Ed25519", NATIVE_PROVIDER);
    final Signature jceSig = Signature.getInstance("Ed25519", "SunEC");

    nativeSig.initSign(kp.getPrivate());
    nativeSig.update(message1, 0, message1.length);
    byte[] signature = nativeSig.sign();

    nativeSig.initVerify(kp.getPublic());
    nativeSig.update(message2, 0, message2.length);
    assertFalse(nativeSig.verify(signature));

    jceSig.initVerify(kp.getPublic());
    jceSig.update(message2, 0, message2.length);
    assertFalse(jceSig.verify(signature));

    // Ed25519ph ("pre-hash") testing below, hash algorithm is always SHA-512
    // https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1
    message1 = MessageDigest.getInstance("SHA-512").digest(message1);
    message2 = MessageDigest.getInstance("SHA-512").digest(message2);

    nativeSig = Signature.getInstance("Ed25519ph", NATIVE_PROVIDER);
    nativeSig.initSign(kp.getPrivate());
    nativeSig.update(message1, 0, message1.length);
    signature = nativeSig.sign();

    nativeSig.initVerify(kp.getPublic());
    nativeSig.update(message2, 0, message2.length);
    assertFalse(nativeSig.verify(signature));

    // JCE interop requires reflection for EdDSAParameterSpec to compile on JDK <15
    if (!ed25519phIsEnabled()) {
      return;
    }

    makeJceSignaturePh(jceSig);

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

  private static void makeJceSignaturePh(Signature sig) {
    assertTrue(ed25519phIsEnabled());
    AlgorithmParameterSpec paramSpec = null;
    try {
      Class<?> eddsaParamSpecClass = Class.forName("java.security.spec.EdDSAParameterSpec");
      assertNotNull(eddsaParamSpecClass);
      Constructor<?> constructor = eddsaParamSpecClass.getConstructor(boolean.class);
      assertNotNull(constructor);
      paramSpec = (AlgorithmParameterSpec) constructor.newInstance(true);
      assertNotNull(paramSpec);
      sig.setParameter(paramSpec);
    } catch (Exception e) {
      e.printStackTrace();
      fail("Failed to create EdDSAParameterSpec", e);
    }
  }
}
