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
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Iterator;
import java.util.zip.GZIPInputStream;
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

  // --- ACVP Signature Verification Test Vectors (from rsaEmsaPssSigVer.rsp.gz) ---

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
    final File rsp = new File(System.getProperty("test.data.dir"), "rsaEmsaPssSigVer.rsp.gz");
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

        // Hash the message to get the digest for RSAEMSA-PSS
        final MessageDigest md = MessageDigest.getInstance(hashAlg, ACCP);
        final byte[] digest = md.digest(message);

        final MGF1ParameterSpec mgfSpec = getMgf1Spec(hashAlg);
        final PSSParameterSpec pssSpec = new PSSParameterSpec(hashAlg, "MGF1", mgfSpec, saltLen, 1);

        final Signature verifier = Signature.getInstance("RSAEMSA-PSS", ACCP);
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

      // Sign with ACCP RSAEMSA-PSS, verify with BC NONEwithRSASSA-PSS
      final Signature accpSigner = Signature.getInstance("RSAEMSA-PSS", ACCP);
      accpSigner.setParameter(pssSpec);
      accpSigner.initSign(kp.getPrivate());
      accpSigner.update(hash);
      final byte[] accpSig = accpSigner.sign();

      final Signature bcVerifier = Signature.getInstance("NONEwithRSASSA-PSS", BC);
      bcVerifier.initVerify(kp.getPublic());
      bcVerifier.setParameter(pssSpec);
      bcVerifier.update(hash);
      assertTrue(bcVerifier.verify(accpSig), "BC failed to verify ACCP sig for " + hashAlg);

      // Sign with BC NONEwithRSASSA-PSS, verify with ACCP RSAEMSA-PSS
      final Signature bcSigner = Signature.getInstance("NONEwithRSASSA-PSS", BC);
      bcSigner.initSign(kp.getPrivate());
      bcSigner.setParameter(pssSpec);
      bcSigner.update(hash);
      final byte[] bcSig = bcSigner.sign();

      final Signature accpVerifier = Signature.getInstance("RSAEMSA-PSS", ACCP);
      accpVerifier.setParameter(pssSpec);
      accpVerifier.initVerify(kp.getPublic());
      accpVerifier.update(hash);
      assertTrue(accpVerifier.verify(bcSig), "ACCP failed to verify BC sig for " + hashAlg);
    }
  }
}
