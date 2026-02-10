// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static org.junit.jupiter.api.Assertions.*;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
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
public class RsaemsaPssTest {
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
}
