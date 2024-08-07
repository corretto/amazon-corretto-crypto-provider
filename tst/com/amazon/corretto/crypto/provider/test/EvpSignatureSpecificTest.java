// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.NATIVE_PROVIDER;
import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static com.amazon.corretto.crypto.provider.test.TestUtil.assumeMinimumVersion;
import static com.amazon.corretto.crypto.provider.test.TestUtil.getJavaVersion;
import static com.amazon.corretto.crypto.provider.test.TestUtil.versionCompare;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPrivateKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * These tests cover cases specific to certain algorithms rather than general to all EvpSignature
 * algorithms.
 */
@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public final class EvpSignatureSpecificTest {
  private static final BouncyCastleProvider BOUNCYCASTLE_PROVIDER = new BouncyCastleProvider();
  private static final byte[] MESSAGE = new byte[513];
  private static final KeyPair RSA_PAIR;
  private static final KeyPair ECDSA_PAIR;

  static {
    for (int x = 0; x < MESSAGE.length; x++) {
      MESSAGE[x] = (byte) ((x % 256) - 128);
    }

    try {
      KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");
      kg.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));
      RSA_PAIR = kg.generateKeyPair();

      kg = KeyPairGenerator.getInstance("EC");
      kg.initialize(new ECGenParameterSpec("NIST P-384"));
      ECDSA_PAIR = kg.generateKeyPair();
    } catch (final GeneralSecurityException ex) {
      throw new RuntimeException(ex);
    }
  }

  /**
   * Returns known bad ECDSA signatures which have confused implementations in the past. (Examples
   * include infinite loops and incorrect acceptance).
   */
  public static List<Arguments> ecdsaBadSignatures() {
    final List<String> algorithms =
        NATIVE_PROVIDER.getServices().stream()
            .filter(service -> "Signature".equalsIgnoreCase(service.getType()))
            .filter(service -> service.getAlgorithm().toUpperCase().contains("ECDSA"))
            .map(Provider.Service::getAlgorithm)
            .collect(Collectors.toList());
    final ECPublicKey pubKey = (ECPublicKey) ECDSA_PAIR.getPublic();
    final BigInteger order = pubKey.getParams().getOrder();

    final List<Arguments> result = new ArrayList<>();
    for (final String algorithm : algorithms) {
      // ECDSA requires that both r and s be within [1, order-1]
      // These seven cases cover all combinations of having one or both elements outside that range.
      result.add(Arguments.of(algorithm, BigInteger.ZERO, BigInteger.ZERO));
      result.add(Arguments.of(algorithm, BigInteger.ZERO, BigInteger.ONE));
      result.add(Arguments.of(algorithm, BigInteger.ONE, BigInteger.ZERO));
      result.add(Arguments.of(algorithm, BigInteger.ZERO, order));
      result.add(Arguments.of(algorithm, order, BigInteger.ZERO));
      result.add(Arguments.of(algorithm, order, BigInteger.ONE));
      result.add(Arguments.of(algorithm, BigInteger.ONE, order));
    }
    return result;
  }

  private static void testKeyTypeMismatch(
      final String algorithm, final String baseType, final KeyPair badKeypair)
      throws GeneralSecurityException {
    final Signature signature = Signature.getInstance(algorithm, NATIVE_PROVIDER);

    assertThrows(InvalidKeyException.class, () -> signature.initSign(badKeypair.getPrivate()));
    assertThrows(InvalidKeyException.class, () -> signature.initVerify(badKeypair.getPublic()));

    // In this case, we are lying about what type of key it is, so it may not be caught until we
    // actually try to use it
    final RawKey fakekey = new RawKey(baseType, badKeypair.getPrivate());
    try {
      signature.initSign(fakekey);
      signature.update(MESSAGE);
      signature.sign();
      fail("Expected exception for fake key");
    } catch (final InvalidKeyException | SignatureException ex) {
      // Expected
    }
  }

  @ParameterizedTest
  @MethodSource("ecdsaBadSignatures")
  @SuppressWarnings("unchecked")
  public void testBadEcdsaSignature(final String algorithm, final BigInteger r, final BigInteger s)
      throws GeneralSecurityException {
    final Signature verifier = Signature.getInstance(algorithm, NATIVE_PROVIDER);
    // We always use the largest key to avoid hash truncation confusion
    final ECPublicKey pubKey = (ECPublicKey) ECDSA_PAIR.getPublic();
    final byte[] signature;
    byte[] rArr = r.toByteArray();
    if (rArr[0] == 0) { // Trim leading zero byte if present
      rArr = Arrays.copyOfRange(rArr, 1, rArr.length);
    }
    byte[] sArr = s.toByteArray();
    if (sArr[0] == 0) { // Trim leading zero byte if present
      sArr = Arrays.copyOfRange(sArr, 1, sArr.length);
    }

    if (algorithm.endsWith("inP1363Format")) {
      // Just zeros of the appropriate length
      final int elementLength = (pubKey.getParams().getOrder().bitLength() + 7) / 8;
      signature = new byte[elementLength * 2];
      System.arraycopy(rArr, 0, signature, elementLength - rArr.length, rArr.length);
      System.arraycopy(sArr, 0, signature, 2 * elementLength - sArr.length, sArr.length);
    } else {
      // It isn't worth building full ASN.1 logic here, so we cover the easy cases of ones and zeros
      // and leave the complicated cases of the full orders to the P1363 tests
      // (which cover the same implementations) under the hood
      assumeTrue(
          rArr.length == 1 && sArr.length == 1,
          "This test only supports {0,1} for non-P1363 sigs.");
      signature = new byte[] {0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00};
      signature[4] = rArr[0];
      signature[7] = sArr[0];
    }
    verifier.initVerify(pubKey);
    try {
      assertFalse(verifier.verify(signature));
    } catch (final SignatureException ex) {
      // We also allow a SignatureException.
    }
  }

  @Test
  public void signatureCorruptionSweeps() throws Exception {
    // Verify that, for any one-bit manipulation of the signature, we 1) get a bad signature result
    // and 2) don't
    // throw an unexpected exception
    doCorruptionSweep("NONEwithECDSA", ECDSA_PAIR);
    doCorruptionSweep("SHA1withECDSA", ECDSA_PAIR);
    doCorruptionSweep("SHA1withRSA", RSA_PAIR);
  }

  private void doCorruptionSweep(final String algorithm, final KeyPair keyPair) throws Exception {
    byte[] message = new byte[] {1, 2, 3, 4};
    byte[] signature;

    Signature sig = Signature.getInstance(algorithm, NATIVE_PROVIDER);
    sig.initSign(keyPair.getPrivate());
    sig.update(message);
    signature = sig.sign();

    sig.initVerify(keyPair.getPublic());

    for (int bitpos = 0; bitpos < signature.length * 8; bitpos++) {
      byte[] badSignature = signature.clone();
      badSignature[bitpos / 8] ^= (1 << (bitpos % 8));

      sig.update(message);
      try {
        assertFalse(sig.verify(badSignature));
      } catch (SignatureException ex) {
        if (algorithm.contains("RSA")) {
          // RSA is not allowed to fail with an exception
          throw ex;
        }
      } catch (Throwable t) {
        throw new RuntimeException("Exception at bitpos " + bitpos, t);
      }
    }
  }

  @Test
  public void rsaWithEcdsaKey() throws GeneralSecurityException {
    testKeyTypeMismatch("SHA1withRSA", "RSA", ECDSA_PAIR);
  }

  @Test
  public void ecdsaWithRsaKey() throws GeneralSecurityException {
    testKeyTypeMismatch("SHA1withECDSA", "EC", RSA_PAIR);
  }

  @Test
  public void pssParametersForNonPssAlgorithm() throws GeneralSecurityException {
    Signature signature = Signature.getInstance("SHA1withRSA", NATIVE_PROVIDER);
    assertNull(signature.getParameters());

    try {
      signature.setParameter(PSSParameterSpec.DEFAULT);
      fail(signature.getAlgorithm());
    } catch (final InvalidAlgorithmParameterException ex) {
      // expected
    }

    signature = Signature.getInstance("SHA1withECDSA", NATIVE_PROVIDER);
    try {
      signature.setParameter(PSSParameterSpec.DEFAULT);
      fail(signature.getAlgorithm());
    } catch (final InvalidAlgorithmParameterException ex) {
      // expected
    }
  }

  @SuppressWarnings("deprecation")
  @Test
  public void deprecatedParameterLogic() throws GeneralSecurityException {
    final Signature signature = Signature.getInstance("SHA1withRSA", NATIVE_PROVIDER);
    assertThrows(
        UnsupportedOperationException.class,
        () -> {
          signature.getParameter("PSS");
        });
    assertThrows(
        UnsupportedOperationException.class,
        () -> {
          signature.setParameter("PSS", null);
        });
  }

  @Test
  public void uninitialized() throws GeneralSecurityException {
    final Signature signature = Signature.getInstance("SHA1withRSA", NATIVE_PROVIDER);
    assertThrows(SignatureException.class, () -> signature.update(MESSAGE));
  }

  @Test
  public void wrongMode() throws GeneralSecurityException {
    final Signature signature = Signature.getInstance("SHA1withRSA", NATIVE_PROVIDER);
    signature.initSign(RSA_PAIR.getPrivate());
    signature.update(MESSAGE);
    try {
      signature.verify(new byte[128]);
      fail();
    } catch (final SignatureException ex) {
      // expected
    }

    signature.initVerify(RSA_PAIR.getPublic());
    signature.update(MESSAGE);
    try {
      signature.sign();
      fail();
    } catch (final SignatureException ex) {
      // expected
    }
  }

  @Test
  public void reinitImmediately() throws Exception {
    final Signature signature = Signature.getInstance("SHA1withRSA", NATIVE_PROVIDER);
    signature.initVerify(RSA_PAIR.getPublic());
    signature.initSign(RSA_PAIR.getPrivate());
    signature.update(MESSAGE);

    final Signature bcSig = Signature.getInstance("SHA1withRSA", BOUNCYCASTLE_PROVIDER);
    bcSig.initVerify(RSA_PAIR.getPublic());
    bcSig.update(MESSAGE);
    assertTrue(bcSig.verify(signature.sign()));
  }

  @Test
  public void reinitAfterData() throws Exception {
    final Signature signature = Signature.getInstance("SHA1withRSA", NATIVE_PROVIDER);
    signature.initVerify(RSA_PAIR.getPublic());
    signature.update(MESSAGE);
    signature.initSign(RSA_PAIR.getPrivate());
    signature.update(MESSAGE);

    final Signature bcSig = Signature.getInstance("SHA1withRSA", BOUNCYCASTLE_PROVIDER);
    bcSig.initVerify(RSA_PAIR.getPublic());
    bcSig.update(MESSAGE);
    assertTrue(bcSig.verify(signature.sign()));
  }

  @Test
  public void reinitAfterLotsOfData() throws Exception {
    final Signature signature = Signature.getInstance("SHA1withRSA", NATIVE_PROVIDER);
    signature.initVerify(RSA_PAIR.getPublic());
    for (int x = 0; x < 512; x++) {
      signature.update(MESSAGE);
    }
    signature.initSign(RSA_PAIR.getPrivate());
    signature.update(MESSAGE);

    final Signature bcSig = Signature.getInstance("SHA1withRSA", BOUNCYCASTLE_PROVIDER);
    bcSig.initVerify(RSA_PAIR.getPublic());
    bcSig.update(MESSAGE);
    assertTrue(bcSig.verify(signature.sign()));
  }

  @Test
  public void testBadArrayParams() throws Exception {
    final Signature signature = Signature.getInstance("SHA1withRSA", NATIVE_PROVIDER);
    signature.initVerify(RSA_PAIR.getPublic());

    assertThrows(IllegalArgumentException.class, () -> signature.update(MESSAGE, -1, 1));
    assertThrows(
        IllegalArgumentException.class, () -> signature.update(MESSAGE, 0, MESSAGE.length + 1));
    assertThrows(
        IllegalArgumentException.class, () -> signature.update(MESSAGE, 10, MESSAGE.length - 1));
    assertThrows(IllegalArgumentException.class, () -> signature.update(MESSAGE, 0, -5));
    assertThrows(
        IllegalArgumentException.class, () -> signature.update(MESSAGE, 2, Integer.MAX_VALUE));

    final byte[] fakeSignature = new byte[2048];
    assertThrows(IllegalArgumentException.class, () -> signature.verify(fakeSignature, -1, 1));
    assertThrows(
        IllegalArgumentException.class,
        () -> signature.verify(fakeSignature, 0, fakeSignature.length + 1));
    assertThrows(
        IllegalArgumentException.class,
        () -> signature.verify(fakeSignature, 10, fakeSignature.length - 1));
    assertThrows(IllegalArgumentException.class, () -> signature.verify(fakeSignature, 0, -5));
    assertThrows(
        IllegalArgumentException.class,
        () -> signature.verify(fakeSignature, 2, Integer.MAX_VALUE));
  }

  @Test
  public void testRsaWithoutCrtParams() throws Exception {
    final RSAPrivateKey prvKey = (RSAPrivateKey) RSA_PAIR.getPrivate();
    final KeyFactory kf = KeyFactory.getInstance("RSA", NATIVE_PROVIDER);
    final PrivateKey strippedKey =
        kf.generatePrivate(new RSAPrivateKeySpec(prvKey.getModulus(), prvKey.getPrivateExponent()));
    final Signature signature = Signature.getInstance("SHA1withRSA", NATIVE_PROVIDER);
    signature.initSign(strippedKey);
    signature.update(MESSAGE);
    final byte[] validSignature = signature.sign();
    signature.initVerify(RSA_PAIR.getPublic());
    signature.update(MESSAGE);
    assertTrue(signature.verify(validSignature));
  }

  @Test
  public void testDigestTooLargeForSmallKey() throws Exception {
    // NOTE: AWS-LC enforces a minimum modulus size of 512 bits for key
    //       generation, so we need to specify the smaller key manually.
    final BigInteger n =
        new BigInteger(
            "010800185049102889923150759252557522305032794699952150943573164381936603255999071981574575044810461362008102247767482738822150129277490998033971789476107463");
    final BigInteger d =
        new BigInteger(
            "0161169735844219697954459962296126719476357984292128166117072108359155865913405986839960884870654387514883422519600695753920562880636800379454345804879553");
    assertTrue(n.bitCount() < 256);
    assertTrue(d.bitCount() < 256);
    final KeyFactory kf = KeyFactory.getInstance("RSA", NATIVE_PROVIDER);
    final PrivateKey privateKey = kf.generatePrivate(new RSAPrivateKeySpec(n, d));
    final Signature signer = Signature.getInstance("SHA512withRSA", NATIVE_PROVIDER);
    signer.initSign((RSAPrivateKey) privateKey);
    try {
      signer.sign();
      assertFalse(true);
    } catch (SignatureException e) {
      assertTrue(e.getMessage().contains("DIGEST_TOO_BIG_FOR_RSA_KEY"));
    }
  }

  @Test
  public void testRsaPSSBadParams() throws Exception {
    // Test bad digest algorithms for PSS and its MGF1
    String[] badDigests = {"MD-5", "MD-4", "garbage", "", "SHA-3"};
    final Signature signature = Signature.getInstance("RSASSA-PSS", NATIVE_PROVIDER);
    final PSSParameterSpec spec;
    for (String badDigest : badDigests) {
      assertThrows(
          InvalidAlgorithmParameterException.class,
          () ->
              signature.setParameter(
                  new PSSParameterSpec(badDigest, "MGF1", MGF1ParameterSpec.SHA1, 20, 1)));
      assertThrows(
          InvalidAlgorithmParameterException.class,
          () ->
              signature.setParameter(
                  new PSSParameterSpec("SHA-1", "MGF1", new MGF1ParameterSpec(badDigest), 20, 1)));
      // Also, "MGF1" should be the only valid MGF, badDigest is general garbage so use it here
      assertThrows(
          InvalidAlgorithmParameterException.class,
          () ->
              signature.setParameter(
                  new PSSParameterSpec("SHA-1", badDigest, MGF1ParameterSpec.SHA1, 20, 1)));
    }

    // Negative salt lengths are reserved, and we can never allow larger than our max key size
    // NOTE: PSSParameterSpec also checks for saltLen < 0, and throws IllegalArgumentException
    assertThrows(
        IllegalArgumentException.class,
        () ->
            signature.setParameter(
                new PSSParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, -1, 1)));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            signature.setParameter(
                new PSSParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, 4096, 1)));

    // Assert compatibility with JCE on setting null parameter. BC doesn't throw. The test is
    // skipped for JDK 10. SunRsaSign in JDK 10 doesn't support RSASSA-PSS signature algorithm, and
    // it throws "java.security.NoSuchAlgorithmException: no such algorithm: RSASSA-PSS for provider
    // SunRsaSign".
    assertThrows(InvalidAlgorithmParameterException.class, () -> signature.setParameter(null));
    if (getJavaVersion() != 10) {
      assertThrows(
          InvalidAlgorithmParameterException.class,
          () -> Signature.getInstance("RSASSA-PSS", "SunRsaSign").setParameter(null));
    }
    Signature.getInstance("RSASSA-PSS", TestUtil.BC_PROVIDER).setParameter(null);

    // "1" should be only valid trailer value.
    for (int ii = -10; ii < 11; ii++) {
      if (ii == 1) {
        continue;
      }
      final int trailer = ii;
      assertThrows(
          IllegalArgumentException.class,
          () ->
              signature.setParameter(
                  new PSSParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, 20, trailer)));
    }
  }

  @Test
  public void testRsaPSSDefaultsToSha1() throws Exception {
    final KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA", NATIVE_PROVIDER);
    kg.initialize(2048);
    final KeyPair pair = kg.generateKeyPair();
    Signature signature;
    PSSParameterSpec spec;

    signature = Signature.getInstance("RSASSA-PSS", NATIVE_PROVIDER);
    signature.initSign(pair.getPrivate());
    spec = getPssParams(signature);
    assertEquals("SHA-1", spec.getDigestAlgorithm());
    assertEquals("SHA-1", ((MGF1ParameterSpec) spec.getMGFParameters()).getDigestAlgorithm());

    signature = Signature.getInstance("RSASSA-PSS", NATIVE_PROVIDER);
    signature.initVerify(pair.getPublic());
    spec = getPssParams(signature);
    assertEquals("SHA-1", spec.getDigestAlgorithm());
    assertEquals("SHA-1", ((MGF1ParameterSpec) spec.getMGFParameters()).getDigestAlgorithm());
  }

  @Test
  void testRsaPSSTryUpdateParamDuringBuffer() throws Exception {
    final KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA", NATIVE_PROVIDER);
    kg.initialize(2048);
    final KeyPair pair = kg.generateKeyPair();
    final Signature signer = Signature.getInstance("RSASSA-PSS", NATIVE_PROVIDER);
    final Signature verifier = Signature.getInstance("RSASSA-PSS", NATIVE_PROVIDER);
    final PSSParameterSpec spec1 =
        new PSSParameterSpec("SHA-224", "MGF1", MGF1ParameterSpec.SHA224, 224 / 8, 1);
    final PSSParameterSpec spec2 =
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 256 / 8, 1);

    // Initialize signatures and set non-default PSS parameters
    signer.initSign(pair.getPrivate());
    verifier.initVerify(pair.getPublic());
    signer.setParameter(spec1);
    verifier.setParameter(spec1);

    // Assert that set values persisted
    assertPssParamsEqual(spec1, getPssParams(signer));
    assertPssParamsEqual(spec1, getPssParams(verifier));

    // Update message digest, assert that we can't upate params, and that signature verifies.
    signer.update(MESSAGE);
    verifier.update(MESSAGE);
    assertThrows(IllegalStateException.class, () -> signer.setParameter(spec2));
    assertThrows(IllegalStateException.class, () -> verifier.setParameter(spec2));
    assertTrue(verifier.verify(signer.sign()));

    // Finally, assert that we can set params after sign/verify reinit
    signer.setParameter(spec2);
    verifier.setParameter(spec2);
    assertPssParamsEqual(spec2, getPssParams(signer));
    assertPssParamsEqual(spec2, getPssParams(verifier));
  }

  // RSASSA-PSS not available on Java10, so skip the test if we can't get get a AlgorithmParameters
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
    assertEquals(s1.getDigestAlgorithm(), s2.getDigestAlgorithm());
    assertEquals(
        ((MGF1ParameterSpec) s1.getMGFParameters()).getDigestAlgorithm(),
        ((MGF1ParameterSpec) s2.getMGFParameters()).getDigestAlgorithm());
  }

  @Test
  void testRsaPSSInitSmallKeyAfterSetParameterLargeSaltThrows() throws Exception {
    assumeFalse(TestUtil.isFips(), "In FIPS mode, smallKeySize cannot be less that 2048");
    final int minimallySecureKeyLen = 2048;
    final int smallKeySize = minimallySecureKeyLen / 4;
    final Signature signer = Signature.getInstance("RSASSA-PSS", NATIVE_PROVIDER);
    final int largeSaltLen = 2 * (smallKeySize / 8);
    final PSSParameterSpec spec =
        new PSSParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, largeSaltLen, 1);

    // Set PSS params _before_ initializing for signer. No access to key length yet, so assuming a
    // default of 2048.
    signer.setParameter(spec);

    // Now, initialize the signature with a smaller key
    final KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA", NATIVE_PROVIDER);
    kg.initialize(smallKeySize);
    KeyPair pair = kg.generateKeyPair();
    signer.initSign(pair.getPrivate());

    // Assert that doFinal (i.e. the native method called in signer.sign()) detects overly large
    // salt len and throws
    byte[] shortMessage = new byte[] {(byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF};
    signer.update(shortMessage);
    assertThrows(SignatureException.class, () -> signer.sign());

    // After re-initializing with minimally secure RSA key, longer salt len set earlier should be
    // fine.
    kg.initialize(minimallySecureKeyLen);
    pair = kg.generateKeyPair();
    signer.initSign(pair.getPrivate());
    signer.update(shortMessage);
    final byte[] signature = signer.sign();

    // For completeness, also verify the data and signature. We don't test verification with the
    // smaller key
    // size because generating a siganture with oversized salt length + undersized key is not
    // possible. If no
    // signature can be generated, there's nothing nothing to verify.
    final Signature verifier = Signature.getInstance("RSASSA-PSS", NATIVE_PROVIDER);
    verifier.setParameter(spec);
    verifier.initVerify(pair.getPublic());
    verifier.update(shortMessage);
    assertTrue(verifier.verify(signature));

    // Generate a valid signature with an undersized key but minimal salt length. Then, bump the
    // salt length
    // for the verifier instance and try to verify the signature. The verification attempt will
    // return false
    // instead of throwing. Apparently AWS-LC doesn't perform relevant validation upon verification.
    PSSParameterSpec spec2 =
        new PSSParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, /*saltLen*/ 20, 1);
    kg.initialize(smallKeySize);
    pair = kg.generateKeyPair();
    signer.setParameter(spec2);
    signer.initSign(pair.getPrivate());
    signer.update(shortMessage);
    final byte[] signature2 = signer.sign();

    spec2 = new PSSParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, largeSaltLen, 1);
    verifier.setParameter(spec2);
    verifier.initVerify(pair.getPublic());
    verifier.update(shortMessage);
    assertFalse(verifier.verify(signature2));
  }

  /**
   * We used to leave undrained openssl errors after parsing ECDSA keys. This could be seen if you
   * immediately had a failed AES-GCM decryption following the ECDSA parse where you'd get the
   * incorrect exception back.
   */
  @Test
  public void ecdsaSignCorruptsErrorState() throws Exception {
    assumeMinimumVersion("1.0.1", NATIVE_PROVIDER);
    final KeyPairGenerator kg = KeyPairGenerator.getInstance("EC", NATIVE_PROVIDER);
    kg.initialize(384);
    final KeyPair pair = kg.generateKeyPair();
    final Signature signer = Signature.getInstance("SHA256withECDSA", NATIVE_PROVIDER);
    signer.initSign(pair.getPrivate());
    signer.sign(); // Ignore result

    Cipher c = Cipher.getInstance("AES/GCM/NoPadding", NATIVE_PROVIDER);
    c.init(
        Cipher.DECRYPT_MODE,
        new SecretKeySpec("Yellow Submarine".getBytes(StandardCharsets.UTF_8), "AES"),
        new GCMParameterSpec(128, new byte[12]));
    try {
      c.doFinal(new byte[32]);
    } catch (final AEADBadTagException ex) {
      // expected
    }
  }

  /**
   * This test iterates over every implemented algorithm and ensures that it is compatible with the
   * equivalent BouncyCastle implementation. It doesn't check negative cases as the more detailed
   * tests cover that for algorithm families.
   */
  @Test
  public void simpleCorrectnessAllAlgorithms() throws Throwable {
    final Pattern namePattern = Pattern.compile("(SHA(\\d+)|NONE)with([A-Z]+)(inP1363Format)?");
    final Set<Provider.Service> services = NATIVE_PROVIDER.getServices();
    for (Provider.Service service : services) {
      final String algorithm = service.getAlgorithm();
      if (!service.getType().equals("Signature") || "RSASSA-PSS".equals(algorithm)) {
        continue;
      }
      if (algorithm.equals("Ed25519") || algorithm.equals("EdDSA")) {
        return;
      }
      String bcAlgorithm = algorithm;
      AlgorithmParameterSpec keyGenSpec = null;
      String keyGenAlgorithm = null;
      final Matcher m = namePattern.matcher(algorithm);

      if (!m.matches()) {
        fail("Unexpected algorithm name: " + algorithm);
      }

      final String shaLength = m.group(2);
      final String base = m.group(3);
      final String ieeeFormat = m.group(4);

      int ffSize = 0; // Finite field size used with RSA
      switch (m.group(1)) {
        case "SHA1":
        case "SHA224":
        case "SHA256":
          ffSize = 2048;
          break;
        case "SHA384":
          ffSize = 3072;
          break;
        case "SHA512":
        case "NONE":
          ffSize = 4096;
          break;
        default:
          fail("Unexpected algorithm name: " + algorithm);
      }
      if ("ECDSA".equals(base)) {
        keyGenAlgorithm = "EC";
        if (null == shaLength
            || "1".equals(shaLength)
            || "224".equals(shaLength)
            || "512".equals(shaLength)) {
          keyGenSpec = new ECGenParameterSpec("NIST P-521");
        } else {
          keyGenSpec = new ECGenParameterSpec("NIST P-" + shaLength);
        }

        if (ieeeFormat != null) {
          bcAlgorithm = bcAlgorithm.replace("withECDSAinP1363Format", "withPLAIN-ECDSA");
        }
      } else {
        keyGenAlgorithm = base;
      }

      final KeyPairGenerator kg = KeyPairGenerator.getInstance(keyGenAlgorithm);
      if (keyGenSpec != null) {
        kg.initialize(keyGenSpec);
      } else {
        kg.initialize(ffSize);
      }
      final KeyPair pair = kg.generateKeyPair();

      final Signature nativeSig = Signature.getInstance(algorithm, NATIVE_PROVIDER);
      final Signature bcSig = Signature.getInstance(bcAlgorithm, TestUtil.BC_PROVIDER);

      simpleCorrectnessSignVerify(algorithm, pair, bcSig, nativeSig);
    }

    // RSASSA-PSS support added in v2.0, skip PSS validation for older versions
    if (versionCompare("2.0.0", NATIVE_PROVIDER) <= 0) {
      return;
    }

    // NOTE: for RSASSA-PSS, test supported digest lengths, but keep PSS and MGF1 digest lengths
    // equal because
    //       BouncyCastle doesn't support differing lengths. we test differing lengths exhaustively
    // against
    //       SuncJCE in EvpSignatureTest. enforce min key size of 2048 bits, consistent with ffSize
    // above.
    for (int shaVersion : new int[] {1, 224, 256, 384, 512}) {
      final String algorithmStr = "RSASSA-PSS";
      final String mdName = String.format("SHA-%d", shaVersion);
      final int mdLen = MessageDigest.getInstance(mdName).getDigestLength();
      final int keySize = mdLen * 8 < 2048 ? 2048 : mdLen * 8;
      final KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA", NATIVE_PROVIDER);
      kg.initialize(keySize);
      final KeyPair pair = kg.generateKeyPair();
      final Signature nativeSig = Signature.getInstance(algorithmStr, NATIVE_PROVIDER);
      final Signature bcSig = Signature.getInstance(algorithmStr, TestUtil.BC_PROVIDER);
      final PSSParameterSpec pssParams =
          new PSSParameterSpec(mdName, "MGF1", new MGF1ParameterSpec(mdName), mdLen, 1);
      nativeSig.setParameter(pssParams);
      bcSig.setParameter(pssParams);

      simpleCorrectnessSignVerify(algorithmStr, pair, bcSig, nativeSig);
    }
  }

  private static void simpleCorrectnessSignVerify(
      String algorithm, KeyPair pair, Signature bcSig, Signature nativeSig) throws Throwable {
    final byte[] message = {1, 2, 3, 4, 5, 6, 7, 8};
    try {
      // Generate with native and verify with BC
      nativeSig.initSign(pair.getPrivate());
      bcSig.initVerify(pair.getPublic());
      nativeSig.update(message);
      bcSig.update(message);
      byte[] signature = nativeSig.sign();
      assertTrue(bcSig.verify(signature), "Native->BC: " + algorithm);

      // Generate with BC and verify with native
      nativeSig.initVerify(pair.getPublic());
      bcSig.initSign(pair.getPrivate());
      nativeSig.update(message);
      bcSig.update(message);
      signature = bcSig.sign();
      assertTrue(nativeSig.verify(signature), "BC->Native: " + algorithm);
    } catch (SignatureException ex) {
      throw new AssertionError(algorithm, ex);
    }
  }

  @Test
  public void ecdsaRejectsNullParams() throws Exception {
    final Signature signer = Signature.getInstance("SHA384withECDSA", NATIVE_PROVIDER);
    signer.initSign(ECDSA_PAIR.getPrivate());
    assertThrows(InvalidAlgorithmParameterException.class, () -> signer.setParameter(null));
    signer.update(MESSAGE);
    final byte[] signature = signer.sign();
    signer.initVerify(ECDSA_PAIR.getPublic());
    assertThrows(InvalidAlgorithmParameterException.class, () -> signer.setParameter(null));
    signer.update(MESSAGE);
    assertTrue(signer.verify(signature));
  }

  @Test
  public void ecdsaAcceptsKeyParams() throws Exception {
    // Some java programs try to set parameters equal to those encoded in the key.
    final ECParameterSpec params = ((ECPrivateKey) ECDSA_PAIR.getPrivate()).getParams();
    final Signature signer = Signature.getInstance("SHA384withECDSA", NATIVE_PROVIDER);
    signer.initSign(ECDSA_PAIR.getPrivate());
    signer.setParameter(params);
    signer.update(MESSAGE);
    final byte[] signature = signer.sign();
    signer.initVerify(ECDSA_PAIR.getPublic());
    signer.setParameter(params);
    signer.update(MESSAGE);
    assertTrue(signer.verify(signature));
  }

  @Test
  public void ecdsaRejectsKeyParams() throws Exception {
    // Some java programs try to set parameters equal to those encoded in the key.
    // If these don't match then they must be rejected.
    // NOTE: If the curve of ECDSA_PAIR changes to P-256 it will invalidate this test.
    final AlgorithmParameters algParams = AlgorithmParameters.getInstance("EC");
    algParams.init(new ECGenParameterSpec("secp256r1"));
    final ECParameterSpec params = algParams.getParameterSpec(ECParameterSpec.class);
    final Signature signer = Signature.getInstance("SHA384withECDSA", NATIVE_PROVIDER);
    signer.initSign(ECDSA_PAIR.getPrivate());
    assertThrows(InvalidAlgorithmParameterException.class, () -> signer.setParameter(params));
  }

  @SuppressWarnings("serial")
  private static class RawKey implements PublicKey, PrivateKey {
    private final String algorithm_;
    private final byte[] encoded_;
    private final String format_;

    public RawKey(final String algorithm, final Key key) {
      this(algorithm, key.getEncoded(), key.getFormat());
    }

    public RawKey(final String algorithm, final byte[] encoded, final String format) {
      algorithm_ = algorithm;
      encoded_ = encoded.clone();
      format_ = format;
    }

    @Override
    public String getAlgorithm() {
      return algorithm_;
    }

    @Override
    public byte[] getEncoded() {
      return encoded_.clone();
    }

    @Override
    public String getFormat() {
      return format_;
    }
  }
}
