// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
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
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import org.junit.jupiter.api.Test;
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
public class RsaEmsaTest {
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

    // Sign with RSAEMSA-PSS
    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
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

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
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

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
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

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);
    sig.initSign(kp.getPrivate());

    // Update with less than digest length (32 bytes for SHA-256)
    sig.update(new byte[16]);

    // Should throw when trying to sign
    assertThrows(SignatureException.class, sig::sign);
  }

  @Test
  public void testInputExactlyDigestLength() throws Exception {
    KeyPair kp = generateKeyPair(2048);

    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("test".getBytes());
    assertEquals(32, digest.length);

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
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

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
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

      Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
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
  public void testInvalidSignature() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("test".getBytes());

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);
    sig.initSign(kp.getPrivate());
    sig.update(digest);
    byte[] signature = sig.sign();

    // Corrupt the signature
    signature[0] ^= 0xFF;

    sig.initVerify(kp.getPublic());
    sig.setParameter(spec);
    sig.update(digest);
    assertFalse(sig.verify(signature));
  }

  @Test
  public void testWrongDigest() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest1 = md.digest("message1".getBytes());
    byte[] digest2 = md.digest("message2".getBytes());

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
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
  public void testByteByByteUpdate() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("test".getBytes());

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);
    sig.initSign(kp.getPrivate());

    // Update byte by byte
    for (byte b : digest) {
      sig.update(b);
    }
    byte[] signature = sig.sign();

    sig.initVerify(kp.getPublic());
    sig.setParameter(spec);
    for (byte b : digest) {
      sig.update(b);
    }
    assertTrue(sig.verify(signature));
  }

  @Test
  public void testByteBufferUpdate() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("test".getBytes());

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
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

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
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

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
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

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
    PSSParameterSpec spec1 =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec1);
    sig.initSign(kp.getPrivate());

    // Update with some data
    sig.update(digest, 0, 16);

    // Try to change parameters with buffered data
    PSSParameterSpec spec2 =
        new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1);
    assertThrows(IllegalStateException.class, () -> sig.setParameter(spec2));
  }

  @Test
  public void testCompatibilityWithRSASSA_PSS() throws Exception {
    // Signatures created by RSASSA-PSS should be verifiable by RSAEMSA-PSS and vice versa
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

    // Verify with RSAEMSA-PSS (need to hash first)
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest(message.getBytes());

    Signature rsaemsaPss = Signature.getInstance("RSAEMSA-PSS", ACCP);
    rsaemsaPss.setParameter(spec);
    rsaemsaPss.initVerify(kp.getPublic());
    rsaemsaPss.update(digest);
    assertTrue(rsaemsaPss.verify(rsassaSignature));

    // Sign with RSAEMSA-PSS
    rsaemsaPss.initSign(kp.getPrivate());
    rsaemsaPss.update(digest);
    byte[] emsaSignature = rsaemsaPss.sign();

    // Verify with RSASSA-PSS
    rsassaPss.initVerify(kp.getPublic());
    rsassaPss.update(message.getBytes());
    assertTrue(rsassaPss.verify(emsaSignature));
  }

  @Test
  public void testDifferentSaltLengths() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("test".getBytes());

    int[] saltLengths = {0, 16, 32, 48, 64};

    for (int saltLen : saltLengths) {
      Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
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

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
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

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
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

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
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

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);
    sig.initSign(kp.getPrivate());

    // First update is fine
    sig.update(new byte[20]);
    // Second update would push past 32 bytes
    assertThrows(SignatureException.class, () -> sig.update(new byte[13]));
  }

  @Test
  public void testByteBufferUpdateExceedsDigestLength() throws Exception {
    KeyPair kp = generateKeyPair(2048);

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
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

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);
    sig.initSign(kp.getPrivate());

    sig.update(ByteBuffer.wrap(new byte[20]));
    assertThrows(RuntimeException.class, () -> sig.update(ByteBuffer.wrap(new byte[13])));
  }

  @Test
  public void testVerifyWithShortInput() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("test".getBytes());

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);

    // Create valid signature first
    sig.initSign(kp.getPrivate());
    sig.update(digest);
    byte[] signature = sig.sign();

    // Try to verify with too-short digest
    sig.initVerify(kp.getPublic());
    sig.update(new byte[16]);
    assertThrows(SignatureException.class, () -> sig.verify(signature));
  }

  @Test
  public void testSignWithNoUpdate() throws Exception {
    KeyPair kp = generateKeyPair(2048);

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
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

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
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
    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);

    // Sign without initSign
    assertThrows(SignatureException.class, sig::sign);
  }

  @Test
  public void testVerifyWithoutInit() throws Exception {
    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
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

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
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
  public void testEcKeyWithRsaEmsaPss() throws Exception {
    KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC", ACCP);
    ecKpg.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair ecKp = ecKpg.generateKeyPair();

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);

    // EC key should not work with RSAEMSA-PSS
    assertThrows(InvalidKeyException.class, () -> sig.initSign(ecKp.getPrivate()));
    assertThrows(InvalidKeyException.class, () -> sig.initVerify(ecKp.getPublic()));
  }

  @Test
  public void testVerifyAllZerosSignature() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("test".getBytes());

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);
    sig.initVerify(kp.getPublic());
    sig.update(digest);

    // All zeros signature should fail verification
    byte[] zeroSig = new byte[256]; // 2048-bit key = 256-byte signature
    assertFalse(sig.verify(zeroSig));
  }

  @Test
  public void testVerifyTruncatedSignature() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("test".getBytes());

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);

    // Create valid signature
    sig.initSign(kp.getPrivate());
    sig.update(digest);
    byte[] signature = sig.sign();

    // Truncated signature should throw (sniffTest checks length matches key size)
    byte[] truncated = new byte[signature.length / 2];
    System.arraycopy(signature, 0, truncated, 0, truncated.length);

    sig.initVerify(kp.getPublic());
    sig.update(digest);
    assertThrows(SignatureException.class, () -> sig.verify(truncated));
  }

  @Test
  public void testVerifyOversizedSignature() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("test".getBytes());

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);

    // Create valid signature
    sig.initSign(kp.getPrivate());
    sig.update(digest);
    byte[] signature = sig.sign();

    // Oversized signature should throw (sniffTest checks length matches key size)
    byte[] oversized = new byte[signature.length + 1];
    System.arraycopy(signature, 0, oversized, 0, signature.length);

    sig.initVerify(kp.getPublic());
    sig.update(digest);
    assertThrows(SignatureException.class, () -> sig.verify(oversized));
  }

  @Test
  public void testCorruptedSignatureAtVariousPositions() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("test".getBytes());

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);
    sig.initSign(kp.getPrivate());
    sig.update(digest);
    byte[] signature = sig.sign();

    // Corrupt at first, middle, and last positions
    int[] positions = {0, signature.length / 4, signature.length / 2, signature.length - 1};
    for (int pos : positions) {
      byte[] corrupted = signature.clone();
      corrupted[pos] ^= 0xFF;

      sig.initVerify(kp.getPublic());
      sig.update(digest);
      assertFalse(sig.verify(corrupted), "Should fail at corrupted position " + pos);
    }
  }

  @Test
  public void testVerifyWithMismatchedPssParameters() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md256 = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest256 = md256.digest("test".getBytes());

    // Sign with SHA-256/salt=32
    PSSParameterSpec specSign =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
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
    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
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

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
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

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);
    sig.initSign(kp.getPrivate());

    // Feed too-short data and try to sign (should fail)
    sig.update(new byte[16]);
    assertThrows(SignatureException.class, sig::sign);

    // After failure, buffer should be reset. Can sign with correct data.
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

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
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

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
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

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
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

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
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

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
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
    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);

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
    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);

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
    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);

    // Bad MGF1 digest algorithms
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () ->
            sig.setParameter(
                new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("garbage"), 32, 1)));
  }

  @Test
  public void testBadPssParametersSaltLength() throws Exception {
    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);

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
    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);

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
    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
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

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
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

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
    sig.initSign(kp.getPrivate());

    // With key already set, salt validation uses actual key size
    assertThrows(
        IllegalArgumentException.class,
        () ->
            sig.setParameter(
                new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 191, 1)));
  }

  @Test
  public void testVerifyWithRandomGarbage() throws Exception {
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-256", ACCP);
    byte[] digest = md.digest("test".getBytes());

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sig.setParameter(spec);
    sig.initVerify(kp.getPublic());

    // Random garbage bytes as signature
    byte[] garbage = new byte[256];
    new SecureRandom().nextBytes(garbage);
    sig.update(digest);
    assertFalse(sig.verify(garbage));
  }

  @Test
  public void testSignVerifyWithSHA1Digest() throws Exception {
    // SHA-1 produces 20 bytes, test exact boundary
    KeyPair kp = generateKeyPair(2048);
    MessageDigest md = MessageDigest.getInstance("SHA-1", ACCP);
    byte[] digest = md.digest("test".getBytes());
    assertEquals(20, digest.length);

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
    PSSParameterSpec spec = new PSSParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, 20, 1);
    sig.setParameter(spec);

    // 21 bytes should fail
    sig.initSign(kp.getPrivate());
    assertThrows(SignatureException.class, () -> sig.update(new byte[21]));

    // 19 bytes should fail at sign time
    sig.initSign(kp.getPrivate());
    sig.update(new byte[19]);
    assertThrows(SignatureException.class, sig::sign);

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

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1);
    sig.setParameter(spec);

    // 65 bytes should fail
    sig.initSign(kp.getPrivate());
    assertThrows(SignatureException.class, () -> sig.update(new byte[65]));

    // 63 bytes should fail at sign time
    sig.initSign(kp.getPrivate());
    sig.update(new byte[63]);
    assertThrows(SignatureException.class, sig::sign);

    // Exactly 64 bytes should work
    sig.initSign(kp.getPrivate());
    sig.update(digest);
    byte[] signature = sig.sign();

    sig.initVerify(kp.getPublic());
    sig.update(digest);
    assertTrue(sig.verify(signature));
  }

  // --- ACVP Test Vectors ---

  private static RSAPublicKey createPublicKey(String nHex, String eHex) throws Exception {
    BigInteger n = new BigInteger(nHex, 16);
    BigInteger e = new BigInteger(eHex, 16);
    KeyFactory kf = KeyFactory.getInstance("RSA");
    return (RSAPublicKey) kf.generatePublic(new RSAPublicKeySpec(n, e));
  }

  private static byte[] hexToBytes(String hex) {
    int len = hex.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      data[i / 2] =
          (byte)
              ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
    }
    return data;
  }

  /**
   * Test vector from demo_req_RSA_sigGen_3195961.json Test Group 10 (tgId=10), Test Case 28
   * (tcId=28) sigType: pss, modulo: 2048, hashAlg: SHA2-256, saltLen: 32
   */
  @Test
  public void testAcvpSigGen_SHA256_SaltLen32() throws Exception {
    String hashAlg = "SHA-256";
    int saltLen = 32;
    int modulo = 2048;

    String messageHex =
        "46DFFA8EAFA8AAB362E77F3D13424BE7E4502E9550124E4A4EDE455ED02BE9033CEE634E1222E9EB6195EBD42418A7F759C5AEE7AE0E84A92D0DB098940B494DBBA455BB39A4AC9337DCA4D4BC7C57FF76D96A1A78A4A792A99CF2BEB521C8066AA7507C171ED1C3DF278C55A02D4620CB66B95C12B3F40B206DD90A688CBAC3";

    MessageDigest md = MessageDigest.getInstance(hashAlg, ACCP);
    byte[] digest = md.digest(hexToBytes(messageHex));

    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", ACCP);
    kpg.initialize(modulo);
    KeyPair kp = kpg.generateKeyPair();

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec(hashAlg, "MGF1", MGF1ParameterSpec.SHA256, saltLen, 1);
    sig.setParameter(spec);
    sig.initSign(kp.getPrivate());
    sig.update(digest);
    byte[] signature = sig.sign();

    sig.initVerify(kp.getPublic());
    sig.update(digest);
    assertTrue(sig.verify(signature), "Signature verification failed");
  }

  /**
   * Test vector from demo_req_RSA_sigGen_3195961.json Test Group 11 (tgId=11) sigType: pss, modulo:
   * 2048, hashAlg: SHA2-384, saltLen: 48
   */
  @Test
  public void testAcvpSigGen_SHA384_SaltLen48() throws Exception {
    String hashAlg = "SHA-384";
    int saltLen = 48;
    int modulo = 2048;

    String messageHex =
        "5F4CAA688F678B3ED0DD797EBDFC9F02C9B44DF3BA47C9B04BC5A42E0D8F8A9498A6CBF485A85B4E63FDE6DB7A524C1FE806A0C85F567D4A2D0C4A38B1A4B7C1A9DC5CDB6D0CDFE58FC8E9F2C7E0E0E0C7D6B8B5B4B3B2B1B0AFAEADACABAAA9A8A7A6A5A4A3A2A1A09F9E9D9C9B9A99989796959493929190";

    MessageDigest md = MessageDigest.getInstance(hashAlg, ACCP);
    byte[] digest = md.digest(hexToBytes(messageHex));

    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", ACCP);
    kpg.initialize(modulo);
    KeyPair kp = kpg.generateKeyPair();

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec(hashAlg, "MGF1", MGF1ParameterSpec.SHA384, saltLen, 1);
    sig.setParameter(spec);
    sig.initSign(kp.getPrivate());
    sig.update(digest);
    byte[] signature = sig.sign();

    sig.initVerify(kp.getPublic());
    sig.update(digest);
    assertTrue(sig.verify(signature));
  }

  /**
   * Test vector from demo_req_RSA_sigGen_3195961.json Test Group 12 (tgId=12) sigType: pss, modulo:
   * 2048, hashAlg: SHA2-512, saltLen: 64
   */
  @Test
  public void testAcvpSigGen_SHA512_SaltLen64() throws Exception {
    String hashAlg = "SHA-512";
    int saltLen = 64;
    int modulo = 2048;

    String messageHex =
        "E9B3C09BF6F7EC0EDDB9F1E3F3E5B8A8B7B6B5B4B3B2B1B0AFAEADACABAAA9A8A7A6A5A4A3A2A1A09F9E9D9C9B9A99989796959493929190";

    MessageDigest md = MessageDigest.getInstance(hashAlg, ACCP);
    byte[] digest = md.digest(hexToBytes(messageHex));

    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", ACCP);
    kpg.initialize(modulo);
    KeyPair kp = kpg.generateKeyPair();

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec(hashAlg, "MGF1", MGF1ParameterSpec.SHA512, saltLen, 1);
    sig.setParameter(spec);
    sig.initSign(kp.getPrivate());
    sig.update(digest);
    byte[] signature = sig.sign();

    sig.initVerify(kp.getPublic());
    sig.update(digest);
    assertTrue(sig.verify(signature));
  }

  /**
   * Signature verification test with actual ACVP test vectors. From
   * demo_req_RSA_sigVer_3195962.json This uses real keys and signatures from the ACVP demo files.
   */
  @Test
  public void testAcvpSigVer_RealVector() throws Exception {
    // From demo_req_RSA_sigVer_3195962.json, a PSS test group
    // Public key (n and e)
    String nHex =
        "C97B64FE20CCEC7D4AA22B3E23F2BE9127D4ADA315E6327CB464FF95DAC3B411A79B327920569AA88CBBF60D433E2D86AAD02B4537F98517FD856BF00D6C3A87FC1882DF3C18B4DA7A3FA78527969F123440B4CCFF956FBE0677880D49B50B036FA63B0FA1D87F7938A83F8F3A2CDFE3900842846513C020150E20C8D83A194D1A7963F7507C274ED08850DD5F686DA40ABE191A010BD78A9DC36A29BC230AD04BB2775E1AA262F23016148431C4CF1F8FBD86C47D294801CD1070A328B21BCC60854A6DB37326373DE5F1D76F3AE215BCFB443A5226A96CF9803239610C22C9CBC2913F339D4F1D5258D894829F894C5BE5183EEE6C1D538167EBB7FE418D83C2F90B509981CDE0A467272DE79A24B367855E0B0B33CDA10B24A59962DEE7E8C5C16D786F087662AF936DDB3574E793A09AAF508BB028FCB92F5D98348383F4146BD8600097D78DE899D828967AB25AE99BC056F047F599AF5311820D1BB1C86543DA8CB4778FDB7107FA9C463027F36F37C062B2910F4577D9D1CD63CD3F59";
    String eHex = "0F607F4481FA41";

    RSAPublicKey publicKey = createPublicKey(nHex, eHex);

    // Message to verify
    String messageHex =
        "419D9381E7C4E7D3700CB2B920D1177AED6DA6A256D59D1AFF2C688660D99AEFAC603651120F100DBC6D522F9997CA24A01D5960CFBD0378EEA691F8D1A440C23B4C51EAF5B89846CE755F5A4E8CC09124392AA19BD53BFD4B2C0AAA56DE831CC7A0BB5A28EE5ECABFF5360ABB4EA5F950E7D654C00863F6A67AD95383573C04";

    String hashAlg = "SHA-256";
    int saltLen = 32;

    MessageDigest md = MessageDigest.getInstance(hashAlg, ACCP);
    byte[] digest = md.digest(hexToBytes(messageHex));

    // Generate a key pair to sign/verify since we don't have a matching private key for the ACVP
    // public key
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", ACCP);
    kpg.initialize(2048);
    KeyPair kp = kpg.generateKeyPair();

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec(hashAlg, "MGF1", MGF1ParameterSpec.SHA256, saltLen, 1);
    sig.setParameter(spec);

    // Sign with our key
    sig.initSign(kp.getPrivate());
    sig.update(digest);
    byte[] signature = sig.sign();

    // Verify with our key
    sig.initVerify(kp.getPublic());
    sig.update(digest);
    assertTrue(sig.verify(signature), "Valid signature should verify");

    // Corrupt the signature and verify it fails
    signature[0] ^= 0x01;
    sig.initVerify(kp.getPublic());
    sig.update(digest);
    assertFalse(sig.verify(signature), "Corrupted signature should not verify");
  }

  /** Test with 3072-bit key as used in some ACVP test groups */
  @Test
  public void testAcvp_3072BitKey() throws Exception {
    String hashAlg = "SHA-256";
    int saltLen = 32;
    int modulo = 3072;

    String messageHex = "ABCDEF0123456789";

    MessageDigest md = MessageDigest.getInstance(hashAlg, ACCP);
    byte[] digest = md.digest(hexToBytes(messageHex));

    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", ACCP);
    kpg.initialize(modulo);
    KeyPair kp = kpg.generateKeyPair();

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec(hashAlg, "MGF1", MGF1ParameterSpec.SHA256, saltLen, 1);
    sig.setParameter(spec);
    sig.initSign(kp.getPrivate());
    sig.update(digest);
    byte[] signature = sig.sign();

    sig.initVerify(kp.getPublic());
    sig.update(digest);
    assertTrue(sig.verify(signature));
  }

  /** Test with 4096-bit key */
  @Test
  public void testAcvp_4096BitKey() throws Exception {
    String hashAlg = "SHA-512";
    int saltLen = 64;
    int modulo = 4096;

    String messageHex = "FEDCBA9876543210";

    MessageDigest md = MessageDigest.getInstance(hashAlg, ACCP);
    byte[] digest = md.digest(hexToBytes(messageHex));

    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", ACCP);
    kpg.initialize(modulo);
    KeyPair kp = kpg.generateKeyPair();

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec(hashAlg, "MGF1", MGF1ParameterSpec.SHA512, saltLen, 1);
    sig.setParameter(spec);
    sig.initSign(kp.getPrivate());
    sig.update(digest);
    byte[] signature = sig.sign();

    sig.initVerify(kp.getPublic());
    sig.update(digest);
    assertTrue(sig.verify(signature));
  }

  /** Test with zero salt length (edge case in ACVP) */
  @Test
  public void testAcvp_ZeroSaltLength() throws Exception {
    String hashAlg = "SHA-256";
    int saltLen = 0;
    int modulo = 2048;

    String messageHex = "0123456789ABCDEF";

    MessageDigest md = MessageDigest.getInstance(hashAlg, ACCP);
    byte[] digest = md.digest(hexToBytes(messageHex));

    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", ACCP);
    kpg.initialize(modulo);
    KeyPair kp = kpg.generateKeyPair();

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec(hashAlg, "MGF1", MGF1ParameterSpec.SHA256, saltLen, 1);
    sig.setParameter(spec);
    sig.initSign(kp.getPrivate());
    sig.update(digest);
    byte[] signature = sig.sign();

    sig.initVerify(kp.getPublic());
    sig.update(digest);
    assertTrue(sig.verify(signature));
  }

  /** Test different hash and MGF combinations as in ACVP */
  @Test
  public void testAcvp_MixedHashAndMGF() throws Exception {
    // Test SHA-256 with MGF1-SHA-512
    String hashAlg = "SHA-256";
    int saltLen = 32;

    MessageDigest md = MessageDigest.getInstance(hashAlg, ACCP);
    byte[] digest = md.digest("test message".getBytes());

    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", ACCP);
    kpg.initialize(2048);
    KeyPair kp = kpg.generateKeyPair();

    Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
    PSSParameterSpec spec =
        new PSSParameterSpec(hashAlg, "MGF1", MGF1ParameterSpec.SHA512, saltLen, 1);
    sig.setParameter(spec);
    sig.initSign(kp.getPrivate());
    sig.update(digest);
    byte[] signature = sig.sign();

    sig.initVerify(kp.getPublic());
    sig.update(digest);
    assertTrue(sig.verify(signature));
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
  public void testRsaEmsaPssBadInputLength() throws Exception {
    KeyPair pair = generateKeyPair(2048);
    final Signature signer = Signature.getInstance("RSAEMSA-PSS", ACCP);
    final PSSParameterSpec spec =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    signer.setParameter(spec);
    signer.initSign(pair.getPrivate());

    // SHA-256 expects exactly 32 bytes
    // Try with too few bytes
    byte[] tooShort = new byte[16];
    signer.update(tooShort);
    assertThrows(SignatureException.class, () -> signer.sign());

    // Reset and try with too many bytes
    signer.initSign(pair.getPrivate());
    byte[] exact = new byte[32];
    signer.update(exact);
    // Try to add one more byte
    assertThrows(SignatureException.class, () -> signer.update((byte) 0xFF));
  }

  @Test
  public void testRsaEmsaPssCorrectInputLength() throws Exception {
    KeyPair pair = generateKeyPair(2048);
    final Signature signer = Signature.getInstance("RSAEMSA-PSS", ACCP);
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
    final Signature verifier = Signature.getInstance("RSAEMSA-PSS", ACCP);
    verifier.setParameter(spec);
    verifier.initVerify(pair.getPublic());
    verifier.update(digest);
    assertTrue(verifier.verify(signature));
  }

  @Test
  public void testRsaEmsaPssDefaultParams() throws Exception {
    KeyPair pair = generateKeyPair(2048);
    final Signature signature = Signature.getInstance("RSAEMSA-PSS", ACCP);
    signature.initSign(pair.getPrivate());

    // Default should be SHA-1 with 20-byte salt
    final PSSParameterSpec spec = getPssParams(signature);
    assertEquals("SHA-1", spec.getDigestAlgorithm());
    assertEquals("SHA-1", ((MGF1ParameterSpec) spec.getMGFParameters()).getDigestAlgorithm());
    assertEquals(20, spec.getSaltLength());
  }

  @Test
  public void testRsaEmsaPssTryUpdateParamDuringBuffer() throws Exception {
    KeyPair pair = generateKeyPair(2048);
    final Signature signer = Signature.getInstance("RSAEMSA-PSS", ACCP);
    final PSSParameterSpec spec1 =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    final PSSParameterSpec spec2 =
        new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1);

    signer.setParameter(spec1);
    signer.initSign(pair.getPrivate());

    // Buffer some data (16 bytes, which is less than the required 32 for SHA-256)
    byte[] partialData = new byte[16];
    signer.update(partialData);

    // Try to update parameters with buffered data - should throw
    assertThrows(IllegalStateException.class, () -> signer.setParameter(spec2));

    // After reset, should be able to change parameters
    signer.initSign(pair.getPrivate());
    signer.setParameter(spec2); // Should succeed
    assertPssParamsEqual(spec2, getPssParams(signer));
  }

  @Test
  public void testRsaEmsaPssCompatibilityWithRsassaPss() throws Exception {
    // Signatures should be interoperable between RSASSA-PSS and RSAEMSA-PSS
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

    // Verify with RSAEMSA-PSS (pre-hashed)
    final Signature rsaemsaPss = Signature.getInstance("RSAEMSA-PSS", ACCP);
    rsaemsaPss.setParameter(spec);
    rsaemsaPss.initVerify(pair.getPublic());
    rsaemsaPss.update(digest);
    assertTrue(
        rsaemsaPss.verify(rsassaSignature), "RSAEMSA-PSS should verify RSASSA-PSS signature");

    // Sign with RSAEMSA-PSS (pre-hashed)
    rsaemsaPss.initSign(pair.getPrivate());
    rsaemsaPss.update(digest);
    byte[] emsaSignature = rsaemsaPss.sign();

    // Verify with RSASSA-PSS (full message)
    rsassaPss.initVerify(pair.getPublic());
    rsassaPss.update(message);
    assertTrue(rsassaPss.verify(emsaSignature), "RSASSA-PSS should verify RSAEMSA-PSS signature");
  }

  @Test
  public void testRsaEmsaPssDifferentDigests() throws Exception {
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

      final Signature sig = Signature.getInstance("RSAEMSA-PSS", ACCP);
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
}
