// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Iterator;
import java.util.stream.Stream;
import java.util.zip.GZIPInputStream;
import javax.crypto.Cipher;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

@Execution(ExecutionMode.CONCURRENT)
@ExtendWith(TestResultLogger.class)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class NoneWithRsaTest {
  private static final Provider ACCP = AmazonCorrettoCryptoProvider.INSTANCE;

  private KeyPair generateKeyPair(int keySize) throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", ACCP);
    kpg.initialize(keySize);
    return kpg.generateKeyPair();
  }

  @Test
  public void testBasicSignVerify() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    String message = "Hello, World!";

    // Hash the message
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest(message.getBytes());

    // Sign with NONEwithRSASSA-PSS
    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);
    sig.initSign(kp.getPrivate());
    sig.update(digest);
    byte[] signature = sig.sign();

    assertNotNull(signature);
    assertTrue(signature.length > 0);

    // Verify
    sig.initVerify(kp.getPublic());
    sig.setParameter(spec);
    sig.update(digest);
    assertTrue(sig.verify(signature));
  }

  @Test
  public void testDefaultParameters() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    String message = "Test message";

    // Default is SHA-1 with MGF1-SHA-1 and salt length 20
    MessageDigest md = MessageDigest.getInstance("SHA-1", ACCP);
    byte[] digest = md.digest(message.getBytes());

    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    sig.initSign(kp.getPrivate());
    sig.update(digest);
    byte[] signature = sig.sign();

    sig.initVerify(kp.getPublic());
    sig.update(digest);
    assertTrue(sig.verify(signature));
  }

  @Test
  public void testInputExceedsDigestLength() throws Exception {
    KeyPair kp = generateKeyPair(2048);

    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("test".getBytes());

    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);
    sig.initSign(kp.getPrivate());

    // Try to update with more than digest length
    sig.update(digest);
    assertThrows(SignatureException.class, () -> sig.update((byte) 0xFF));
  }

  @Test
  public void testInputLessThanDigestLength() throws Exception {
    KeyPair kp = generateKeyPair(2048);

    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);
    sig.initSign(kp.getPrivate());

    // Update with less than digest length (32 bytes for SHA-256) should throw immediately
    assertThrows(SignatureException.class, () -> sig.update(new byte[16]));
  }

  @Test
  public void testInputExactlyDigestLength() throws Exception {
    KeyPair kp = generateKeyPair(2048);

    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("test".getBytes());
    assertEquals(32, digest.length);

    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);
    sig.initSign(kp.getPrivate());
    sig.update(digest);
    byte[] signature = sig.sign();

    assertNotNull(signature);
  }

  @ParameterizedTest
  @ValueSource(ints = {2048, 3072, 4096})
  public void testVariousKeySizes(int keySize) throws Exception {
    KeyPair kp = generateKeyPair(keySize);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("test".getBytes());

    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);
    sig.initSign(kp.getPrivate());
    sig.update(digest);
    byte[] signature = sig.sign();

    sig.initVerify(kp.getPublic());
    sig.update(digest);
    assertTrue(sig.verify(signature));
  }

  @Test
  public void testDifferentDigests() throws Exception {
    String[] digests = {"SHA-1", "SHA-256", "SHA-384", "SHA-512"};
    MGF1ParameterSpec[] mgfSpecs = {
      MGF1ParameterSpec.SHA1,
      MGF1ParameterSpec.SHA256,
      MGF1ParameterSpec.SHA384,
      MGF1ParameterSpec.SHA512
    };
    int[] saltLengths = {20, 32, 48, 64};

    KeyPair kp = generateKeyPair(2048);

    for (int i = 0; i < digests.length; i++) {
      MessageDigest md = MessageDigest.getInstance(digests[i], ACCP);
      byte[] digest = md.digest("test message".getBytes());

      Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
      PSSParameterSpec spec =
          new PSSParameterSpec(digests[i], "MGF1", mgfSpecs[i], saltLengths[i], 1);
      sig.setParameter(spec);
      sig.initSign(kp.getPrivate());
      sig.update(digest);
      byte[] signature = sig.sign();

      sig.initVerify(kp.getPublic());
      sig.setParameter(spec);
      sig.update(digest);
      assertTrue(sig.verify(signature), "Failed for " + digests[i]);
    }
  }

  @Test
  public void testWrongDigest() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest1 = md.digest("message1".getBytes());
    byte[] digest2 = md.digest("message2".getBytes());

    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);
    sig.initSign(kp.getPrivate());
    sig.update(digest1);
    byte[] signature = sig.sign();

    // Verify with different digest
    sig.initVerify(kp.getPublic());
    sig.setParameter(spec);
    sig.update(digest2);
    assertFalse(sig.verify(signature));
  }

  @Test
  public void testByteByByteUpdateThrows() throws Exception {
    KeyPair kp = generateKeyPair(2048);

    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);
    sig.initSign(kp.getPrivate());

    // Byte-by-byte update is not supported for one-shot signature
    assertThrows(SignatureException.class, () -> sig.update((byte) 0x42));
  }

  @Test
  public void testByteBufferUpdate() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("test".getBytes());

    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);
    sig.initSign(kp.getPrivate());
    sig.update(ByteBuffer.wrap(digest));
    byte[] signature = sig.sign();

    sig.initVerify(kp.getPublic());
    sig.setParameter(spec);
    sig.update(ByteBuffer.wrap(digest));
    assertTrue(sig.verify(signature));
  }

  @Test
  public void testDirectByteBuffer() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("test".getBytes());

    ByteBuffer directBuf = ByteBuffer.allocateDirect(digest.length);
    directBuf.put(digest);
    directBuf.flip();

    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);
    sig.initSign(kp.getPrivate());
    sig.update(directBuf);
    byte[] signature = sig.sign();

    directBuf.rewind();
    sig.initVerify(kp.getPublic());
    sig.setParameter(spec);
    sig.update(directBuf);
    assertTrue(sig.verify(signature));
  }

  @Test
  public void testReadOnlyByteBuffer() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("test".getBytes());

    ByteBuffer readOnlyBuf = ByteBuffer.wrap(digest).asReadOnlyBuffer();

    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);
    sig.initSign(kp.getPrivate());
    sig.update(readOnlyBuf);
    byte[] signature = sig.sign();

    readOnlyBuf.rewind();
    sig.initVerify(kp.getPublic());
    sig.setParameter(spec);
    sig.update(readOnlyBuf);
    assertTrue(sig.verify(signature));
  }

  @Test
  public void testParameterUpdateRestriction() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("test".getBytes());

    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    PSSParameterSpec spec1 =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec1);
    sig.initSign(kp.getPrivate());

    // Update with complete digest
    sig.update(digest);

    // Try to change parameters with buffered data
    PSSParameterSpec spec2 =
        new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1);
    assertThrows(IllegalStateException.class, () -> sig.setParameter(spec2));
  }

  @Test
  public void testCompatibilityWithRSASSA_PSS() throws Exception {
    // Signatures created by RSASSA-PSS should be verifiable by NONEwithRSASSA-PSS and vice versa
    KeyPair kp = generateKeyPair(2048);
    String message = "Test message for compatibility";

    // Sign with RSASSA-PSS
    Signature rsassaPss = Signature.getInstance("RSASSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    rsassaPss.setParameter(spec);
    rsassaPss.initSign(kp.getPrivate());
    rsassaPss.update(message.getBytes());
    byte[] rsassaSignature = rsassaPss.sign();

    // Verify with NONEwithRSASSA-PSS (need to hash first)
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest(message.getBytes());

    Signature noneWithRsaPss = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    noneWithRsaPss.setParameter(spec);
    noneWithRsaPss.initVerify(kp.getPublic());
    noneWithRsaPss.update(digest);
    assertTrue(noneWithRsaPss.verify(rsassaSignature));

    // Sign with NONEwithRSASSA-PSS
    noneWithRsaPss.initSign(kp.getPrivate());
    noneWithRsaPss.update(digest);
    byte[] noneWithRsaSignature = noneWithRsaPss.sign();

    // Verify with RSASSA-PSS
    rsassaPss.initVerify(kp.getPublic());
    rsassaPss.update(message.getBytes());
    assertTrue(rsassaPss.verify(noneWithRsaSignature));
  }

  @Test
  public void testSignRsassaPssVerifyNoneWithRsaPss() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    byte[] message = "Sign with RSASSA-PSS, verify with NONEwithRSASSA-PSS".getBytes();
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);

    // Sign with RSASSA-PSS (takes raw message, hashes internally)
    Signature signer = Signature.getInstance("RSASSA-PSS", ACCP);
    signer.setParameter(spec);
    signer.initSign(kp.getPrivate());
    signer.update(message);
    byte[] signature = signer.sign();

    // Verify with NONEwithRSASSA-PSS (takes pre-hashed message)
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest(message);

    Signature verifier = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    verifier.setParameter(spec);
    verifier.initVerify(kp.getPublic());
    verifier.update(digest);
    assertTrue(verifier.verify(signature));
  }

  @Test
  public void testSignNoneWithRsaPssVerifyNoneWithRsassaPss() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    byte[] message = "Sign with NONEwithRSASSA-PSS, verify with RSASSA-PSS".getBytes();
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);

    // Sign with NONEwithRSASSA-PSS (takes pre-hashed message)
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest(message);

    Signature signer = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    signer.setParameter(spec);
    signer.initSign(kp.getPrivate());
    signer.update(digest);
    byte[] signature = signer.sign();

    // Verify with RSASSA-PSS (takes raw message, hashes internally)
    Signature verifier = Signature.getInstance("RSASSA-PSS", ACCP);
    verifier.setParameter(spec);
    verifier.initVerify(kp.getPublic());
    verifier.update(message);
    assertTrue(verifier.verify(signature));
  }

  @Test
  public void testDifferentSaltLengths() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("test".getBytes());

    int[] saltLengths = {0, 16, 32, 48, 64};

    for (int saltLen : saltLengths) {
      Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
      PSSParameterSpec spec =
          new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, saltLen, 1);
      sig.setParameter(spec);
      sig.initSign(kp.getPrivate());
      sig.update(digest);
      byte[] signature = sig.sign();

      sig.initVerify(kp.getPublic());
      sig.setParameter(spec);
      sig.update(digest);
      assertTrue(sig.verify(signature), "Failed for salt length " + saltLen);
    }
  }

  @Test
  public void testMultipleSignatures() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);

    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);
    sig.initSign(kp.getPrivate());

    // Sign multiple messages
    for (int i = 0; i < 10; i++) {
      byte[] digest = md.digest(("message" + i).getBytes());
      sig.update(digest);
      byte[] signature = sig.sign();

      sig.initVerify(kp.getPublic());
      sig.update(digest);
      assertTrue(sig.verify(signature));

      // Reinitialize for next signature
      sig.initSign(kp.getPrivate());
    }
  }

  @Test
  public void testVerifyOffsetLength() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("test".getBytes());

    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);
    sig.initSign(kp.getPrivate());
    sig.update(digest);
    byte[] signature = sig.sign();

    // Add padding around signature
    byte[] paddedSig = new byte[signature.length + 20];
    System.arraycopy(signature, 0, paddedSig, 10, signature.length);

    sig.initVerify(kp.getPublic());
    sig.update(digest);
    assertTrue(sig.verify(paddedSig, 10, signature.length));
  }

  // --- Negative / Error Tests ---

  @Test
  public void testArrayUpdateExceedsDigestLength() throws Exception {
    KeyPair kp = generateKeyPair(2048);

    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);
    sig.initSign(kp.getPrivate());

    // Array update with more than 32 bytes should throw
    assertThrows(SignatureException.class, () -> sig.update(new byte[33]));
  }

  @Test
  public void testArrayUpdateExceedsDigestLengthInTwoParts() throws Exception {
    KeyPair kp = generateKeyPair(2048);

    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);
    sig.initSign(kp.getPrivate());

    // First update with wrong length should throw (one-shot: must be exactly 32 bytes)
    assertThrows(SignatureException.class, () -> sig.update(new byte[20]));
  }

  @Test
  public void testByteBufferUpdateExceedsDigestLength() throws Exception {
    KeyPair kp = generateKeyPair(2048);

    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);
    sig.initSign(kp.getPrivate());

    // ByteBuffer with more than 32 bytes should throw (wrapped in RuntimeException)
    ByteBuffer buf = ByteBuffer.wrap(new byte[33]);
    assertThrows(RuntimeException.class, () -> sig.update(buf));
  }

  @Test
  public void testByteBufferUpdateExceedsDigestLengthInTwoParts() throws Exception {
    KeyPair kp = generateKeyPair(2048);

    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);
    sig.initSign(kp.getPrivate());

    // First update with wrong length should throw (one-shot: must be exactly 32 bytes)
    assertThrows(RuntimeException.class, () -> sig.update(ByteBuffer.wrap(new byte[20])));
  }

  @Test
  public void testVerifyWithShortInput() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("test".getBytes());

    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);

    // Create valid signature first
    sig.initSign(kp.getPrivate());
    sig.update(digest);
    byte[] signature = sig.sign();

    // Try to verify with too-short digest - should throw at update time
    sig.initVerify(kp.getPublic());
    assertThrows(SignatureException.class, () -> sig.update(new byte[16]));
  }

  @Test
  public void testSignWithNoUpdate() throws Exception {
    KeyPair kp = generateKeyPair(2048);

    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);
    sig.initSign(kp.getPrivate());

    // Sign without any update (buffer empty, 0 != 32)
    assertThrows(SignatureException.class, sig::sign);
  }

  @Test
  public void testVerifyWithNoUpdate() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("test".getBytes());

    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);

    // Create valid signature
    sig.initSign(kp.getPrivate());
    sig.update(digest);
    byte[] signature = sig.sign();

    // Verify without any update (buffer empty)
    sig.initVerify(kp.getPublic());
    assertThrows(SignatureException.class, () -> sig.verify(signature));
  }

  @Test
  public void testSignWithoutInit() throws Exception {
    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);

    // Sign without initSign
    assertThrows(SignatureException.class, sig::sign);
  }

  @Test
  public void testVerifyWithoutInit() throws Exception {
    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);

    // Verify without initVerify
    assertThrows(SignatureException.class, () -> sig.verify(new byte[256]));
  }

  @Test
  public void testWrongKeyForVerification() throws Exception {
    KeyPair kp1 = generateKeyPair(2048);
    KeyPair kp2 = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("test".getBytes());

    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);

    // Sign with key1
    sig.initSign(kp1.getPrivate());
    sig.update(digest);
    byte[] signature = sig.sign();

    // Verify with key2 (different key pair)
    sig.initVerify(kp2.getPublic());
    sig.update(digest);
    assertFalse(sig.verify(signature));
  }

  @Test
  public void testEcKeyWithNoneWithRsaPss() throws Exception {
    KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC", ACCP);
    ecKpg.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair ecKp = ecKpg.generateKeyPair();

    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);

    // EC key should not work with NONEwithRSASSA-PSS
    assertThrows(InvalidKeyException.class, () -> sig.initSign(ecKp.getPrivate()));
    assertThrows(InvalidKeyException.class, () -> sig.initVerify(ecKp.getPublic()));
  }

  // --- Unified bad-signature tests for both NONEwithRSA and NONEwithRSASSA-PSS ---

  private static Stream<String> badSignatureAlgorithms() {
    return Stream.of("NONEwithRSA", "NONEwithRSASSA-PSS");
  }

  private Signature initSignerForAlgorithm(String algorithm, KeyPair kp) throws Exception {
    Signature sig = Signature.getInstance(algorithm, ACCP);
    if (algorithm.equals("NONEwithRSASSA-PSS")) {
      sig.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
    }
    sig.initSign(kp.getPrivate());
    return sig;
  }

  private Signature initVerifierForAlgorithm(String algorithm, KeyPair kp) throws Exception {
    Signature sig = Signature.getInstance(algorithm, ACCP);
    if (algorithm.equals("NONEwithRSASSA-PSS")) {
      sig.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
    }
    sig.initVerify(kp.getPublic());
    return sig;
  }

  private byte[] signDigest(String algorithm, KeyPair kp, byte[] digest) throws Exception {
    Signature sig = initSignerForAlgorithm(algorithm, kp);
    sig.update(digest);
    return sig.sign();
  }

  @ParameterizedTest
  @MethodSource("badSignatureAlgorithms")
  public void testVerifyCorruptedSignatureAtVariousPositions(String algorithm) throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("test".getBytes());
    byte[] signature = signDigest(algorithm, kp, digest);

    int[] positions = {0, signature.length / 4, signature.length / 2, signature.length - 1};
    for (int pos : positions) {
      byte[] corrupted = signature.clone();
      corrupted[pos] ^= 0xFF;

      Signature verifier = initVerifierForAlgorithm(algorithm, kp);
      verifier.update(digest);
      assertFalse(
          verifier.verify(corrupted), algorithm + " should fail at corrupted position " + pos);
    }
  }

  @ParameterizedTest
  @MethodSource("badSignatureAlgorithms")
  public void testVerifyTruncatedSignature(String algorithm) throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("test".getBytes());
    byte[] signature = signDigest(algorithm, kp, digest);

    byte[] truncated = Arrays.copyOf(signature, signature.length / 2);
    Signature verifier = initVerifierForAlgorithm(algorithm, kp);
    verifier.update(digest);
    assertThrows(SignatureException.class, () -> verifier.verify(truncated));
  }

  @ParameterizedTest
  @MethodSource("badSignatureAlgorithms")
  public void testVerifyOversizedSignature(String algorithm) throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("test".getBytes());
    byte[] signature = signDigest(algorithm, kp, digest);

    byte[] oversized = new byte[signature.length + 1];
    System.arraycopy(signature, 0, oversized, 0, signature.length);
    Signature verifier = initVerifierForAlgorithm(algorithm, kp);
    verifier.update(digest);
    assertThrows(SignatureException.class, () -> verifier.verify(oversized));
  }

  @ParameterizedTest
  @MethodSource("badSignatureAlgorithms")
  public void testVerifyAllZerosSignature(String algorithm) throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("test".getBytes());

    Signature verifier = initVerifierForAlgorithm(algorithm, kp);
    verifier.update(digest);
    assertFalse(verifier.verify(new byte[256]));
  }

  @ParameterizedTest
  @MethodSource("badSignatureAlgorithms")
  public void testVerifyRandomGarbage(String algorithm) throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("test".getBytes());

    byte[] garbage = new byte[256];
    new SecureRandom().nextBytes(garbage);
    Signature verifier = initVerifierForAlgorithm(algorithm, kp);
    verifier.update(digest);
    assertFalse(verifier.verify(garbage));
  }

  @Test
  public void testVerifyWithMismatchedPssParameters() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md256 = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest256 = md256.digest("test".getBytes());

    // Sign with SHA-256/salt=32
    PSSParameterSpec specSign =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    sig.setParameter(specSign);
    sig.initSign(kp.getPrivate());
    sig.update(digest256);
    byte[] signature = sig.sign();

    // Verify with SHA-256 but different salt length
    PSSParameterSpec specVerify =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 16, 1);
    sig.setParameter(specVerify);
    sig.initVerify(kp.getPublic());
    sig.update(digest256);
    assertFalse(sig.verify(signature), "Mismatched salt length should fail");
  }

  @Test
  public void testVerifyWithMismatchedMgfHash() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("test".getBytes());

    // Sign with MGF1-SHA-256
    PSSParameterSpec specSign =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    sig.setParameter(specSign);
    sig.initSign(kp.getPrivate());
    sig.update(digest);
    byte[] signature = sig.sign();

    // Verify with MGF1-SHA-512
    PSSParameterSpec specVerify =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA512, 32, 1);
    sig.setParameter(specVerify);
    sig.initVerify(kp.getPublic());
    sig.update(digest);
    assertFalse(sig.verify(signature), "Mismatched MGF hash should fail");
  }

  @Test
  public void testBufferResetsAfterSign() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);

    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);
    sig.initSign(kp.getPrivate());

    // Sign once
    byte[] digest1 = md.digest("message1".getBytes());
    sig.update(digest1);
    byte[] sig1 = sig.sign();

    // Buffer should be reset. Can sign again with different data.
    byte[] digest2 = md.digest("message2".getBytes());
    sig.update(digest2);
    byte[] sig2 = sig.sign();

    // Both signatures should be valid for their respective digests
    sig.initVerify(kp.getPublic());
    sig.update(digest1);
    assertTrue(sig.verify(sig1));

    sig.initVerify(kp.getPublic());
    sig.update(digest2);
    assertTrue(sig.verify(sig2));
  }

  @Test
  public void testBufferResetsAfterFailedSign() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);

    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);
    sig.initSign(kp.getPrivate());

    // Feed wrong-length data (should fail at update time)
    assertThrows(SignatureException.class, () -> sig.update(new byte[16]));

    // Sign with no data should also fail (buffer empty)
    assertThrows(SignatureException.class, sig::sign);

    // After failure, should be able to sign with correct data.
    byte[] digest = md.digest("test".getBytes());
    sig.update(digest);
    byte[] signature = sig.sign();

    sig.initVerify(kp.getPublic());
    sig.update(digest);
    assertTrue(sig.verify(signature));
  }

  @Test
  public void testBufferResetsAfterVerify() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("test".getBytes());

    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);

    // Sign
    sig.initSign(kp.getPrivate());
    sig.update(digest);
    byte[] signature = sig.sign();

    // Verify (should succeed)
    sig.initVerify(kp.getPublic());
    sig.update(digest);
    assertTrue(sig.verify(signature));

    // Buffer should be reset after verify. Can verify again.
    sig.update(digest);
    assertTrue(sig.verify(signature));
  }

  @Test
  public void testBufferResetsAfterFailedVerify() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("test".getBytes());

    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);

    // Sign
    sig.initSign(kp.getPrivate());
    sig.update(digest);
    byte[] signature = sig.sign();

    // Corrupt and verify (should fail)
    byte[] corrupted = signature.clone();
    corrupted[0] ^= 0xFF;
    sig.initVerify(kp.getPublic());
    sig.update(digest);
    assertFalse(sig.verify(corrupted));

    // Buffer should be reset. Can verify the correct signature now.
    sig.update(digest);
    assertTrue(sig.verify(signature));
  }

  @Test
  public void testMultipleConsecutiveFailedVerifications() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("test".getBytes());

    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);

    // Create valid signature
    sig.initSign(kp.getPrivate());
    sig.update(digest);
    byte[] signature = sig.sign();

    sig.initVerify(kp.getPublic());

    // Multiple consecutive failed verifications (ensures error queue is properly drained each time)
    for (int i = 0; i < 5; i++) {
      byte[] corrupted = signature.clone();
      corrupted[i % signature.length] ^= 0xFF;
      sig.update(digest);
      assertFalse(sig.verify(corrupted), "Failed verification iteration " + i);
    }

    // After all failures, a valid verification should still work
    sig.update(digest);
    assertTrue(sig.verify(signature));
  }

  @Test
  public void testSignInVerifyModeThrows() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("test".getBytes());

    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);

    // Init for verify, try to sign
    sig.initVerify(kp.getPublic());
    sig.update(digest);
    assertThrows(SignatureException.class, sig::sign);
  }

  @Test
  public void testVerifyInSignModeThrows() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("test".getBytes());

    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);

    // Init for sign, try to verify
    sig.initSign(kp.getPrivate());
    sig.update(digest);
    assertThrows(SignatureException.class, () -> sig.verify(new byte[256]));
  }

  @Test
  public void testBadPssParametersDigest() throws Exception {
    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);

    // Bad digest algorithms
    String[] badDigests = {"MD-5", "garbage", "", "SHA-3"};
    for (String badDigest : badDigests) {
      assertThrows(
          InvalidAlgorithmParameterException.class,
          () ->
              sig.setParameter(
                  new PSSParameterSpec(badDigest, "MGF1", MGF1ParameterSpec.SHA256, 32, 1)));
    }
  }

  @Test
  public void testBadPssParametersMgf() throws Exception {
    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);

    // Bad MGF algorithms
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () ->
            sig.setParameter(
                new PSSParameterSpec("SHA-256", "MGF2", MGF1ParameterSpec.SHA256, 32, 1)));
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () ->
            sig.setParameter(
                new PSSParameterSpec("SHA-256", "garbage", MGF1ParameterSpec.SHA256, 32, 1)));
  }

  @Test
  public void testBadPssParametersMgfDigest() throws Exception {
    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);

    // Bad MGF1 digest algorithms
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () ->
            sig.setParameter(
                new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("garbage"), 32, 1)));
  }

  @Test
  public void testBadPssParametersSaltLength() throws Exception {
    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);

    // Negative salt length
    assertThrows(
        IllegalArgumentException.class,
        () ->
            sig.setParameter(
                new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, -1, 1)));

    // Extremely large salt length
    assertThrows(
        IllegalArgumentException.class,
        () ->
            sig.setParameter(
                new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 4096, 1)));
  }

  @Test
  public void testBadPssParametersTrailer() throws Exception {
    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);

    // Only trailer value 1 is valid
    assertThrows(
        IllegalArgumentException.class,
        () ->
            sig.setParameter(
                new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 0)));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            sig.setParameter(
                new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 2)));
  }

  @Test
  public void testNullPssParameters() throws Exception {
    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    assertThrows(InvalidAlgorithmParameterException.class, () -> sig.setParameter(null));
  }

  @Test
  public void testPartialArrayUpdate() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("test".getBytes());

    // Embed digest in a larger array and update with offset/length
    byte[] larger = new byte[digest.length + 20];
    System.arraycopy(digest, 0, larger, 10, digest.length);

    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);
    sig.initSign(kp.getPrivate());
    sig.update(larger, 10, digest.length);
    byte[] signature = sig.sign();

    // Verify using direct digest
    sig.initVerify(kp.getPublic());
    sig.update(digest);
    assertTrue(sig.verify(signature));
  }

  @Test
  public void testSaltLengthTooLargeForKey() throws Exception {
    // Salt must satisfy: salt <= emLen - hLen - 2
    // For 2048-bit key + SHA-512: salt <= 256 - 64 - 2 = 190
    // Salt = 191 exceeds the limit, rejected at setParameter time
    KeyPair kp = generateKeyPair(2048);

    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    sig.initSign(kp.getPrivate());

    // With key already set, salt validation uses actual key size
    assertThrows(
        IllegalArgumentException.class,
        () ->
            sig.setParameter(
                new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 191, 1)));
  }

  @Test
  public void testSignVerifyWithSHA1Digest() throws Exception {
    // SHA-1 produces 20 bytes, test exact boundary
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-1", ACCP);
    byte[] digest = md.digest("test".getBytes());
    assertEquals(20, digest.length);

    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    PSSParameterSpec spec = new PSSParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, 20, 1);
    sig.setParameter(spec);

    // 21 bytes should fail
    sig.initSign(kp.getPrivate());
    assertThrows(SignatureException.class, () -> sig.update(new byte[21]));

    // 19 bytes should fail at update time (one-shot: must be exactly 20)
    sig.initSign(kp.getPrivate());
    assertThrows(SignatureException.class, () -> sig.update(new byte[19]));

    // Exactly 20 bytes should work
    sig.initSign(kp.getPrivate());
    sig.update(digest);
    byte[] signature = sig.sign();

    sig.initVerify(kp.getPublic());
    sig.update(digest);
    assertTrue(sig.verify(signature));
  }

  @Test
  public void testSignVerifyWithSHA512Digest() throws Exception {
    // SHA-512 produces 64 bytes, test exact boundary
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-512", ACCP);
    byte[] digest = md.digest("test".getBytes());
    assertEquals(64, digest.length);

    Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1);
    sig.setParameter(spec);

    // 65 bytes should fail
    sig.initSign(kp.getPrivate());
    assertThrows(SignatureException.class, () -> sig.update(new byte[65]));

    // 63 bytes should fail at update time (one-shot: must be exactly 64)
    sig.initSign(kp.getPrivate());
    assertThrows(SignatureException.class, () -> sig.update(new byte[63]));

    // Exactly 64 bytes should work
    sig.initSign(kp.getPrivate());
    sig.update(digest);
    byte[] signature = sig.sign();

    sig.initVerify(kp.getPublic());
    sig.update(digest);
    assertTrue(sig.verify(signature));
  }

  // --- ACVP Signature Verification Test Vectors (from noneWithRsaPssSigVer.rsp.gz) ---

  private static MGF1ParameterSpec getMgf1Spec(String hashAlg) {
    switch (hashAlg) {
      case "SHA-256":
        return MGF1ParameterSpec.SHA256;
      case "SHA-384":
        return MGF1ParameterSpec.SHA384;
      case "SHA-512":
        return MGF1ParameterSpec.SHA512;
      default:
        throw new IllegalArgumentException("Unsupported hash: " + hashAlg);
    }
  }

  @Test
  public void testAcvpSigVer() throws Exception {
    final File rsp = new File(System.getProperty("test.data.dir"), "noneWithRsaPssSigVer.rsp.gz");
    int testCount = 0;
    try (final InputStream is = new GZIPInputStream(new FileInputStream(rsp))) {
      final Iterator<RspTestEntry> iterator = RspTestEntry.iterateOverResource(is);
      while (iterator.hasNext()) {
        final RspTestEntry entry = iterator.next();

        final String hashAlg = entry.getHeader("hashAlg");
        final int saltLen = Integer.parseInt(entry.getHeader("saltLen"));
        final BigInteger n = new BigInteger(entry.getHeader("n"), 16);
        final BigInteger e = new BigInteger(entry.getHeader("e"), 16);
        final RSAPublicKey publicKey =
            (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));

        final byte[] message = entry.getInstanceFromHex("Msg");
        final byte[] sig = entry.getInstanceFromHex("S");
        final boolean expectedPass = "P".equals(entry.getInstance("Result"));

        // Hash the message to get the digest for NONEwithRSASSA-PSS
        final MessageDigest md = MessageDigest.getInstance(hashAlg, ACCP);
        final byte[] digest = md.digest(message);

        final MGF1ParameterSpec mgfSpec = getMgf1Spec(hashAlg);
        final PSSParameterSpec pssSpec = new PSSParameterSpec(hashAlg, "MGF1", mgfSpec, saltLen, 1);

        final Signature verifier = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
        verifier.setParameter(pssSpec);
        verifier.initVerify(publicKey);
        verifier.update(digest);
        final boolean result = verifier.verify(sig);

        assertEquals(
            expectedPass,
            result,
            "tc "
                + entry.getInstance("Msg").substring(0, 16)
                + "... expected "
                + (expectedPass ? "P" : "F"));
        testCount++;
      }
    }
    assertTrue(testCount > 0, "No test vectors were loaded");
  }

  // --- Tests moved from EvpSignatureSpecificTest ---

  // RSASSA-PSS not available on Java10, so skip the test if we can't get an AlgorithmParameters
  // object for it
  private static PSSParameterSpec getPssParams(Signature signature) {
    try {
      final AlgorithmParameters params = signature.getParameters();
      return params.getParameterSpec(PSSParameterSpec.class);
    } catch (UnsupportedOperationException | GeneralSecurityException e) {
      assumeTrue(false, "Current JDK doesn't support RSASSA-PSS: " + e.getMessage());
      return null; // unreachable, appeases the compiler/linter;
    }
  }

  private static void assertPssParamsEqual(PSSParameterSpec s1, PSSParameterSpec s2) {
    assertEquals(s1.getDigestAlgorithm(), s2.getDigestAlgorithm());
    assertEquals(
        ((MGF1ParameterSpec) s1.getMGFParameters()).getDigestAlgorithm(),
        ((MGF1ParameterSpec) s2.getMGFParameters()).getDigestAlgorithm());
  }

  @Test
  public void testNoneWithRsaPssBadInputLength() throws Exception {
    KeyPair pair = generateKeyPair(2048);
    final Signature signer = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    final PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    signer.setParameter(spec);
    signer.initSign(pair.getPrivate());

    // SHA-256 expects exactly 32 bytes
    // Try with too few bytes - should fail at update time
    assertThrows(SignatureException.class, () -> signer.update(new byte[16]));

    // Reset and try with too many bytes
    signer.initSign(pair.getPrivate());
    assertThrows(SignatureException.class, () -> signer.update(new byte[33]));

    // Reset and try exact length then one more byte
    signer.initSign(pair.getPrivate());
    signer.update(new byte[32]);
    // Try to add one more byte (one-shot: buffer already has data)
    assertThrows(SignatureException.class, () -> signer.update((byte) 0xFF));
  }

  @Test
  public void testNoneWithRsaPssCorrectInputLength() throws Exception {
    KeyPair pair = generateKeyPair(2048);
    final Signature signer = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    final PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    signer.setParameter(spec);
    signer.initSign(pair.getPrivate());

    // Exactly 32 bytes for SHA-256
    byte[] digest = new byte[32];
    new java.util.Random().nextBytes(digest);
    signer.update(digest);
    byte[] signature = signer.sign(); // Should succeed

    // Verify
    final Signature verifier = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    verifier.setParameter(spec);
    verifier.initVerify(pair.getPublic());
    verifier.update(digest);
    assertTrue(verifier.verify(signature));
  }

  @Test
  public void testNoneWithRsaPssDefaultParams() throws Exception {
    KeyPair pair = generateKeyPair(2048);
    final Signature signature = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    signature.initSign(pair.getPrivate());

    // Default should be SHA-1 with 20-byte salt
    final PSSParameterSpec spec = getPssParams(signature);
    assertEquals("SHA-1", spec.getDigestAlgorithm());
    assertEquals("SHA-1", ((MGF1ParameterSpec) spec.getMGFParameters()).getDigestAlgorithm());
    assertEquals(20, spec.getSaltLength());
  }

  @Test
  public void testNoneWithRsaPssTryUpdateParamDuringBuffer() throws Exception {
    KeyPair pair = generateKeyPair(2048);
    final Signature signer = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    final PSSParameterSpec spec1 =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    final PSSParameterSpec spec2 =
        new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1);

    signer.setParameter(spec1);
    signer.initSign(pair.getPrivate());

    // Buffer exact digest (32 bytes for SHA-256)
    signer.update(new byte[32]);

    // Try to update parameters with buffered data - should throw
    assertThrows(IllegalStateException.class, () -> signer.setParameter(spec2));

    // After reset, should be able to change parameters
    signer.initSign(pair.getPrivate());
    signer.setParameter(spec2); // Should succeed
    assertPssParamsEqual(spec2, getPssParams(signer));
  }

  @Test
  public void testNoneWithRsaPssCompatibilityWithRsassaPss() throws Exception {
    // Signatures should be interoperable between RSASSA-PSS and NONEwithRSASSA-PSS
    KeyPair pair = generateKeyPair(2048);
    final byte[] message = "Test message for compatibility".getBytes();
    final String hashAlg = "SHA-256";

    // Hash the message
    final MessageDigest md = MessageDigest.getInstance(hashAlg, ACCP);
    final byte[] digest = md.digest(message);

    final PSSParameterSpec spec =
        new PSSParameterSpec(hashAlg, "MGF1", MGF1ParameterSpec.SHA256, 32, 1);

    // Sign with RSASSA-PSS (full message)
    final Signature rsassaPss = Signature.getInstance("RSASSA-PSS", ACCP);
    rsassaPss.setParameter(spec);
    rsassaPss.initSign(pair.getPrivate());
    rsassaPss.update(message);
    byte[] rsassaSignature = rsassaPss.sign();

    // Verify with NONEwithRSASSA-PSS (pre-hashed)
    final Signature noneWithRsaPss = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
    noneWithRsaPss.setParameter(spec);
    noneWithRsaPss.initVerify(pair.getPublic());
    noneWithRsaPss.update(digest);
    assertTrue(
        noneWithRsaPss.verify(rsassaSignature),
        "NONEwithRSASSA-PSS should verify RSASSA-PSS signature");

    // Sign with NONEwithRSASSA-PSS (pre-hashed)
    noneWithRsaPss.initSign(pair.getPrivate());
    noneWithRsaPss.update(digest);
    byte[] noneWithRsaSignature = noneWithRsaPss.sign();

    // Verify with RSASSA-PSS (full message)
    rsassaPss.initVerify(pair.getPublic());
    rsassaPss.update(message);
    assertTrue(
        rsassaPss.verify(noneWithRsaSignature),
        "RSASSA-PSS should verify NONEwithRSASSA-PSS signature");
  }

  @Test
  public void testNoneWithRsaPssDifferentDigests() throws Exception {
    KeyPair pair = generateKeyPair(2048);

    // Test different digest algorithms
    String[] digests = {"SHA-1", "SHA-256", "SHA-384", "SHA-512"};
    MGF1ParameterSpec[] mgfSpecs = {
      MGF1ParameterSpec.SHA1,
      MGF1ParameterSpec.SHA256,
      MGF1ParameterSpec.SHA384,
      MGF1ParameterSpec.SHA512
    };

    for (int i = 0; i < digests.length; i++) {
      final MessageDigest md = MessageDigest.getInstance(digests[i], ACCP);
      final int digestLen = md.getDigestLength();
      final byte[] digest = new byte[digestLen];
      new java.util.Random().nextBytes(digest);

      final Signature sig = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
      final PSSParameterSpec spec =
          new PSSParameterSpec(digests[i], "MGF1", mgfSpecs[i], digestLen, 1);
      sig.setParameter(spec);
      sig.initSign(pair.getPrivate());
      sig.update(digest);
      byte[] signature = sig.sign();

      sig.initVerify(pair.getPublic());
      sig.update(digest);
      assertTrue(sig.verify(signature), "Failed for " + digests[i]);
    }
  }

  @Test
  public void testBouncyCastleInterop() throws Exception {
    final Provider BC = TestUtil.BC_PROVIDER;
    final KeyPair kp = generateKeyPair(2048);
    final byte[] message = "BouncyCastle interop test".getBytes();

    final String[] digests = {"SHA-1", "SHA-256", "SHA-384", "SHA-512"};
    final MGF1ParameterSpec[] mgfSpecs = {
      MGF1ParameterSpec.SHA1,
      MGF1ParameterSpec.SHA256,
      MGF1ParameterSpec.SHA384,
      MGF1ParameterSpec.SHA512
    };
    final int[] saltLengths = {20, 32, 48, 64};

    for (int i = 0; i < digests.length; i++) {
      final String hashAlg = digests[i];
      final MGF1ParameterSpec mgfSpec = mgfSpecs[i];
      final int saltLen = saltLengths[i];

      final MessageDigest md = MessageDigest.getInstance(hashAlg, ACCP);
      final byte[] hash = md.digest(message);

      final PSSParameterSpec pssSpec = new PSSParameterSpec(hashAlg, "MGF1", mgfSpec, saltLen, 1);

      // Sign with ACCP NONEwithRSASSA-PSS, verify with BC NONEwithRSASSA-PSS
      final Signature accpSigner = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
      accpSigner.setParameter(pssSpec);
      accpSigner.initSign(kp.getPrivate());
      accpSigner.update(hash);
      final byte[] accpSig = accpSigner.sign();

      final Signature bcVerifier = Signature.getInstance("NONEwithRSASSA-PSS", BC);
      bcVerifier.initVerify(kp.getPublic());
      bcVerifier.setParameter(pssSpec);
      bcVerifier.update(hash);
      assertTrue(bcVerifier.verify(accpSig), "BC failed to verify ACCP sig for " + hashAlg);

      // Sign with BC NONEwithRSASSA-PSS, verify with ACCP NONEwithRSASSA-PSS
      final Signature bcSigner = Signature.getInstance("NONEwithRSASSA-PSS", BC);
      bcSigner.initSign(kp.getPrivate());
      bcSigner.setParameter(pssSpec);
      bcSigner.update(hash);
      final byte[] bcSig = bcSigner.sign();

      final Signature accpVerifier = Signature.getInstance("NONEwithRSASSA-PSS", ACCP);
      accpVerifier.setParameter(pssSpec);
      accpVerifier.initVerify(kp.getPublic());
      accpVerifier.update(hash);
      assertTrue(accpVerifier.verify(bcSig), "ACCP failed to verify BC sig for " + hashAlg);
    }
  }

  // --- NONEwithRSA (RSASSA-PKCS1-v1_5 pre-hashed, RFC 8017 Sec. 8.2) tests ---
  // See DIFFERENCES.md for behavioral differences from Sun/BC's NONEwithRSA.

  @Test
  public void testNoneWithRsaBasicSignVerify() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    byte[] message = "Hello, NONEwithRSA!".getBytes();

    // Hash the message
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest(message);

    // Sign with NONEwithRSA
    Signature sig = Signature.getInstance("NONEwithRSA", ACCP);
    sig.initSign(kp.getPrivate());
    sig.update(digest);
    byte[] signature = sig.sign();

    assertNotNull(signature);
    assertTrue(signature.length > 0);

    // Verify
    sig.initVerify(kp.getPublic());
    sig.update(digest);
    assertTrue(sig.verify(signature));
  }

  @Test
  public void testNoneWithRsaDeterministic() throws Exception {
    // PKCS#1 v1.5 is deterministic (unlike PSS which uses random salt)
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("deterministic test".getBytes());

    Signature sig = Signature.getInstance("NONEwithRSA", ACCP);
    sig.initSign(kp.getPrivate());
    sig.update(digest);
    byte[] sig1 = sig.sign();

    sig.initSign(kp.getPrivate());
    sig.update(digest);
    byte[] sig2 = sig.sign();

    assertTrue(Arrays.equals(sig1, sig2), "PKCS#1 v1.5 signatures should be deterministic");
  }

  @Test
  public void testNoneWithRsaDifferentDigests() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    String[] digestAlgs = {"SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"};

    for (String digestAlg : digestAlgs) {
      MessageDigest md = MessageDigest.getInstance(digestAlg);
      byte[] digest = md.digest("test different digests".getBytes());

      Signature sig = Signature.getInstance("NONEwithRSA", ACCP);
      sig.initSign(kp.getPrivate());
      sig.update(digest);
      byte[] signature = sig.sign();

      sig.initVerify(kp.getPublic());
      sig.update(digest);
      assertTrue(sig.verify(signature), "Failed for digest " + digestAlg);
    }
  }

  @ParameterizedTest
  @ValueSource(ints = {2048, 3072, 4096})
  public void testNoneWithRsaDifferentKeySizes(int keySize) throws Exception {
    KeyPair kp = generateKeyPair(keySize);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("test key sizes".getBytes());

    Signature sig = Signature.getInstance("NONEwithRSA", ACCP);
    sig.initSign(kp.getPrivate());
    sig.update(digest);
    byte[] signature = sig.sign();

    sig.initVerify(kp.getPublic());
    sig.update(digest);
    assertTrue(sig.verify(signature), "Failed for key size " + keySize);
  }

  @Test
  public void testNoneWithRsaInputValidation() throws Exception {
    KeyPair kp = generateKeyPair(2048);

    Signature sig = Signature.getInstance("NONEwithRSA", ACCP);

    // Longer than default digest length (32) should succeed and round-trip
    sig.initSign(kp.getPrivate());
    byte[] input33 = new byte[33];
    new SecureRandom().nextBytes(input33);
    sig.update(input33);
    byte[] signature = sig.sign();
    sig.initVerify(kp.getPublic());
    sig.update(input33);
    assertTrue(sig.verify(signature));

    // Shorter than default digest length should succeed and round-trip
    sig.initSign(kp.getPrivate());
    byte[] input16 = new byte[16];
    new SecureRandom().nextBytes(input16);
    sig.update(input16);
    signature = sig.sign();
    sig.initVerify(kp.getPublic());
    sig.update(input16);
    assertTrue(sig.verify(signature));

    // Empty - fails at sign time (no digest provided)
    sig.initSign(kp.getPrivate());
    assertThrows(SignatureException.class, sig::sign);
  }

  @Test
  public void testNoneWithRsaDefaultParams() throws Exception {
    // Default digest should be SHA-256 (32 bytes)
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("default params test".getBytes());
    assertEquals(32, digest.length);

    Signature sig = Signature.getInstance("NONEwithRSA", ACCP);
    sig.initSign(kp.getPrivate());
    sig.update(digest);
    byte[] signature = sig.sign();

    sig.initVerify(kp.getPublic());
    sig.update(digest);
    assertTrue(sig.verify(signature));

    // getParameters should return null for PKCS#1 v1.5
    assertNull(sig.getParameters());
  }

  @Test
  public void testNoneWithRsaSignSha512Digest() throws Exception {
    KeyPair kp = generateKeyPair(2048);

    MessageDigest md = MessageDigest.getInstance("SHA-512", ACCP);
    byte[] digest = md.digest("set params test".getBytes());
    assertEquals(64, digest.length);

    Signature sig = Signature.getInstance("NONEwithRSA", ACCP);
    sig.initSign(kp.getPrivate());
    sig.update(digest);
    byte[] signature = sig.sign();

    sig.initVerify(kp.getPublic());
    sig.update(digest);
    assertTrue(sig.verify(signature));
  }

  private static Stream<Provider> noneWithRsaInteropProviders() {
    return Stream.of(Security.getProvider("SunJCE"), TestUtil.BC_PROVIDER);
  }

  @ParameterizedTest
  @MethodSource("noneWithRsaInteropProviders")
  public void testNoneWithRsaInteropWithOtherProviders(Provider other) throws Exception {
    KeyPair kp = generateKeyPair(2048);
    byte[] message = "NONEwithRSA interop test".getBytes();

    // Both providers sign the same message, signatures must be identical
    Signature accpSigner = Signature.getInstance("NONEwithRSA", ACCP);
    accpSigner.initSign(kp.getPrivate());
    accpSigner.update(message);
    byte[] accpSig = accpSigner.sign();

    Signature otherSigner = Signature.getInstance("NONEwithRSA", other);
    otherSigner.initSign(kp.getPrivate());
    otherSigner.update(message);
    byte[] otherSig = otherSigner.sign();

    assertTrue(
        Arrays.equals(accpSig, otherSig),
        other.getName() + " and ACCP should produce identical signatures");

    // Cross-verify: other verifies ACCP signature
    Signature otherVerifier = Signature.getInstance("NONEwithRSA", other);
    otherVerifier.initVerify(kp.getPublic());
    otherVerifier.update(message);
    assertTrue(otherVerifier.verify(accpSig), other.getName() + " should verify ACCP signature");

    // Cross-verify: ACCP verifies other's signature
    Signature accpVerifier = Signature.getInstance("NONEwithRSA", ACCP);
    accpVerifier.initVerify(kp.getPublic());
    accpVerifier.update(message);
    assertTrue(
        accpVerifier.verify(otherSig), "ACCP should verify " + other.getName() + " signature");
  }

  @Test
  public void testNoneWithRsaSetParameterThrowsCompat() throws Exception {
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1);
    final Signature sunSigner = Signature.getInstance("NONEwithRSA", "SunJCE");
    assertThrows(UnsupportedOperationException.class, () -> sunSigner.setParameter(spec));
    final Signature bcSigner = Signature.getInstance("NONEwithRSA", TestUtil.BC_PROVIDER);
    assertThrows(UnsupportedOperationException.class, () -> bcSigner.setParameter(spec));
    final Signature accpSigner = Signature.getInstance("NONEwithRSA", ACCP);
    assertThrows(UnsupportedOperationException.class, () -> accpSigner.setParameter(spec));
  }

  @Test
  public void testNoneWithRsaCrossAlgorithmInterop() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    byte[] message = "Cross-algorithm interop test".getBytes();

    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest(message);

    // Sign raw digest with NONEwithRSA (no DigestInfo wrapping)
    Signature noneSigner = Signature.getInstance("NONEwithRSA", ACCP);
    noneSigner.initSign(kp.getPrivate());
    noneSigner.update(digest);
    byte[] noneSig = noneSigner.sign();

    // Sign message with SHA256withRSA (hashes internally, wraps digest in DigestInfo)
    Signature sha256Signer = Signature.getInstance("SHA256withRSA", ACCP);
    sha256Signer.initSign(kp.getPrivate());
    sha256Signer.update(message);
    byte[] sha256Sig = sha256Signer.sign();

    // Signatures differ because SHA256withRSA wraps the digest in a DigestInfo struct
    assertFalse(Arrays.equals(noneSig, sha256Sig));

    // Cross-verification should fail
    Signature sha256Verifier = Signature.getInstance("SHA256withRSA", ACCP);
    sha256Verifier.initVerify(kp.getPublic());
    sha256Verifier.update(message);
    assertFalse(
        sha256Verifier.verify(noneSig),
        "SHA256withRSA should NOT verify NONEwithRSA signature (no DigestInfo)");

    Signature noneVerifier = Signature.getInstance("NONEwithRSA", ACCP);
    noneVerifier.initVerify(kp.getPublic());
    noneVerifier.update(digest);
    assertFalse(
        noneVerifier.verify(sha256Sig),
        "NONEwithRSA should NOT verify SHA256withRSA signature (has DigestInfo)");

    // However, the underlying signed content shares the same digest bytes.
    // Decrypt both signatures with raw RSA to recover plaintext, padding stripped.
    Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding", ACCP);
    rsa.init(Cipher.DECRYPT_MODE, kp.getPublic());
    byte[] nonePlain = rsa.doFinal(noneSig);
    assertEquals(digest.length, nonePlain.length); // raw SHA-256 digest, 32 bytes
    rsa.init(Cipher.DECRYPT_MODE, kp.getPublic());
    byte[] sha256Plain = rsa.doFinal(sha256Sig);
    assertEquals(digest.length + 19, sha256Plain.length); // +19 bytes for DigestInfo DER

    // The SHA256withRSA plaintext ends with the same 32-byte digest as the NONEwithRSA plaintext
    byte[] noneDigest =
        Arrays.copyOfRange(nonePlain, nonePlain.length - digest.length, nonePlain.length);
    byte[] sha256Digest =
        Arrays.copyOfRange(sha256Plain, sha256Plain.length - digest.length, sha256Plain.length);
    assertTrue(
        Arrays.equals(noneDigest, sha256Digest),
        "Last 32 bytes (the digest) should be identical in both plaintexts");
    assertTrue(
        Arrays.equals(digest, noneDigest), "Digest bytes should equal the original SHA-256 digest");
  }

  @Test
  public void testEcKeyWithNoneWithRsa() throws Exception {
    KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC", ACCP);
    ecKpg.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair ecKp = ecKpg.generateKeyPair();

    Signature sig = Signature.getInstance("NONEwithRSA", ACCP);

    // EC key should not work with NONEwithRSA
    assertThrows(InvalidKeyException.class, () -> sig.initSign(ecKp.getPrivate()));
    assertThrows(InvalidKeyException.class, () -> sig.initVerify(ecKp.getPublic()));
  }

  @Test
  public void testMessageLargerThanModulusThrows() throws Exception {
    final int keyBits = 4096;
    KeyPair kp = generateKeyPair(keyBits);
    // NOTE: PKCS1 padding is 11 bytes for NONEwithRSA's raw signature
    byte[] goodMsg = new byte[keyBits / 8 - 11];
    byte[] badMsg = new byte[keyBits / 8 - 10];
    new SecureRandom().nextBytes(goodMsg);
    new SecureRandom().nextBytes(badMsg);

    // ACCP: message size of modulus OK
    Signature accpSig = Signature.getInstance("NONEwithRSA", ACCP);
    accpSig.initSign(kp.getPrivate());
    accpSig.update(goodMsg);
    accpSig.sign();

    // SunJCE: message size of modulus OK
    Signature sunSig = Signature.getInstance("NONEwithRSA", "SunJCE");
    sunSig.initSign(kp.getPrivate());
    sunSig.update(goodMsg);
    sunSig.sign();

    // ACCP: accepts update() but rejects at sign(); data too large for key size
    accpSig = Signature.getInstance("NONEwithRSA", ACCP);
    accpSig.initSign(kp.getPrivate());
    accpSig.update(badMsg);
    assertThrows(SignatureException.class, accpSig::sign);

    // SunJCE: accepts update() but rejects at sign(); data too large for key size
    sunSig = Signature.getInstance("NONEwithRSA", "SunJCE");
    sunSig.initSign(kp.getPrivate());
    sunSig.update(badMsg);
    assertThrows(SignatureException.class, sunSig::sign);
  }

  @Test
  public void testNoneWithRsaSetParameterRejectsAllSpecs() throws Exception {
    Signature sig = Signature.getInstance("NONEwithRSA", ACCP);

    // All setParameter calls should be rejected for NONEwithRSA
    assertThrows(UnsupportedOperationException.class, () -> sig.setParameter(null));
    assertThrows(
        UnsupportedOperationException.class,
        () -> sig.setParameter(new ECGenParameterSpec("secp256r1")));
    assertThrows(
        UnsupportedOperationException.class,
        () ->
            sig.setParameter(
                new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)));
  }

  @Test
  public void testNoneWithRsaSetParameterWithBufferedData() throws Exception {
    KeyPair kp = generateKeyPair(2048);

    Signature sig = Signature.getInstance("NONEwithRSA", ACCP);
    sig.initSign(kp.getPrivate());
    sig.update(new byte[32]);

    // setParameter is always rejected for NONEwithRSA, regardless of buffer state
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1);
    assertThrows(UnsupportedOperationException.class, () -> sig.setParameter(spec));
  }

  @Test
  public void testNoneWithRsaSecondUpdateRejected() throws Exception {
    KeyPair kp = generateKeyPair(2048);

    Signature sig = Signature.getInstance("NONEwithRSA", ACCP);
    sig.initSign(kp.getPrivate());

    // First update succeeds (exactly 32 bytes for default SHA-256)
    sig.update(new byte[32]);
    // Second update is rejected (one-shot)
    assertThrows(SignatureException.class, () -> sig.update(new byte[32]));
  }

  @Test
  public void testNoneWithRsaByteBufferSecondUpdateRejected() throws Exception {
    KeyPair kp = generateKeyPair(2048);

    Signature sig = Signature.getInstance("NONEwithRSA", ACCP);
    sig.initSign(kp.getPrivate());

    // First update succeeds
    sig.update(ByteBuffer.wrap(new byte[32]));
    // Second update is rejected (one-shot)
    assertThrows(RuntimeException.class, () -> sig.update(ByteBuffer.wrap(new byte[32])));
  }
}
