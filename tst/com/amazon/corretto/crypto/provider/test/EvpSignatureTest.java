// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static com.amazon.corretto.crypto.provider.test.TestUtil.versionCompare;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.BiFunction;
import java.util.stream.Stream;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

@Execution(ExecutionMode.CONCURRENT)
@ExtendWith(TestResultLogger.class)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class EvpSignatureTest {
  private static final Provider NATIVE_PROVIDER = AmazonCorrettoCryptoProvider.INSTANCE;
  private static final int[] LENGTHS =
      new int[] {1, 3, 4, 7, 8, 16, 32, 48, 64, 128, 256, 1024, 1536, 2049};
  private static final List<String> BASES = Arrays.asList("RSA", "ECDSA");
  private static final List<String> HASHES =
      Arrays.asList("NONE", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512");
  private static final int[] MESSAGE_LENGTHS = new int[] {0, 1, 16, 32, 2047, 2048, 2049, 4100};

  private static class TestParams {
    private final String base;
    private final String algorithm;
    private final AlgorithmParameterSpec paramSpec;
    private final boolean readOnly;
    private final boolean slice;
    private final KeyPair keyPair;
    private final int length;

    private final byte[] message;
    private final Signature signer;
    private final Signature verifier;
    private final Signature jceVerifier;
    private final byte[] goodSignature;

    public TestParams(
        String base,
        String algorithm,
        int length,
        boolean readOnly,
        boolean slice,
        KeyPair keyPair,
        AlgorithmParameterSpec paramSpec)
        throws GeneralSecurityException {
      this.base = base;
      this.algorithm = algorithm;
      this.length = length;
      this.readOnly = readOnly;
      this.slice = slice;
      this.keyPair = keyPair;
      this.paramSpec = paramSpec;

      signer = getNativeSigner();
      if (paramSpec != null) {
        signer.setParameter(paramSpec);
      }
      signer.initSign(keyPair.getPrivate());
      verifier = getNativeSigner();
      if (paramSpec != null) {
        verifier.setParameter(paramSpec);
      }
      verifier.initVerify(keyPair.getPublic());

      jceVerifier = getJceSigner();
      if (paramSpec != null) {
        jceVerifier.setParameter(paramSpec);
      }
      jceVerifier.initVerify(keyPair.getPublic());

      message = new byte[length];

      for (int x = 0; x < message.length; x++) {
        message[x] = (byte) ((x % 256) - 128);
      }

      final Signature jceSigner = getJceSigner();
      if (paramSpec != null) {
        jceSigner.setParameter(paramSpec);
      }
      jceSigner.initSign(keyPair.getPrivate());
      jceSigner.update(message);
      goodSignature = jceSigner.sign();
    }

    @Override
    public String toString() {
      final PSSParameterSpec pssParamSpec = (PSSParameterSpec) paramSpec;
      final String pssParamsStr;
      if (pssParamSpec != null) {
        pssParamsStr =
            String.format(
                "{PSS md: %s, MGF1 md: %s, saltLen: %d}",
                pssParamSpec.getDigestAlgorithm(),
                ((MGF1ParameterSpec) pssParamSpec.getMGFParameters()).getDigestAlgorithm(),
                pssParamSpec.getSaltLength());
      } else {
        pssParamsStr = null;
      }
      return String.format(
          "%s length %s. Read-only: %s, Sliced: %s, PSS: %s",
          algorithm, length, readOnly, slice, pssParamsStr);
    }

    public boolean goodForArraysAndByteBuffers() {
      return readOnly || slice;
    }

    private Signature getNativeSigner() throws NoSuchAlgorithmException {
      return Signature.getInstance(algorithm, NATIVE_PROVIDER);
    }

    private Signature getJceSigner() throws NoSuchAlgorithmException, NoSuchProviderException {
      if ("RSASSA-PSS".equals(algorithm)) {
        // BouncyCastle requires that PSS digest algorithm match MGF1 digest algorithm, which
        // neither we nor other JCE providers require. So, use higest-priority available JCE
        // provider for
        // PSS tests. Some JVMs don't support RSASSA-PSS, so skip the current test case if we can't
        // find
        // an implementation.
        try {
          return Signature.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
          assumeTrue(false, "Current JDK doesn't support RSASSA-PSS: " + e.getMessage());
        }
      }
      final String bcName = algorithm.replace("withECDSAinP1363Format", "withPLAIN-ECDSA");
      return Signature.getInstance(bcName, TestUtil.BC_PROVIDER);
    }

    public int getMessageSizeLimit() {
      // For ECDSA raw algorithms, there is a limit to which the "digest" is truncated. We need to
      // make sure
      // we're not past that limit.

      // Note that ignoring the extension is per the spec - see FIPS.186-4 for ECDSA specifying that
      // the
      // leftmost min(N, outlen) bits of Hash(M) be used, for values of N depending on the domain
      // parameters
      switch (algorithm) {
        case "NONEwithECDSA":
          {
            ECKey ecKey = (ECKey) keyPair.getPublic();

            return ecKey.getParams().getOrder().bitLength() / 8;
          }
        default:
          return Integer.MAX_VALUE;
      }
    }

    public TestParams reset() {
      try {
        signer.initSign(keyPair.getPrivate());
        verifier.initVerify(keyPair.getPublic());
        jceVerifier.initVerify(keyPair.getPublic());
      } catch (final GeneralSecurityException ex) {
        throw new AssertionError(ex);
      }
      return this;
    }
  }

  private static List<TestParams> getParams() throws GeneralSecurityException {
    KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");
    kg.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));
    KeyPair rsaPair = kg.generateKeyPair();

    kg = KeyPairGenerator.getInstance("EC");
    kg.initialize(new ECGenParameterSpec("NIST P-521"));
    KeyPair ecPair = kg.generateKeyPair();

    List<TestParams> paramsList = new ArrayList<>();
    for (final String base : BASES) {
      KeyPair currentPair;
      switch (base) {
        case "RSA":
          currentPair = rsaPair;
          break;
        case "ECDSA":
          currentPair = ecPair;
          break;
        default:
          throw new AssertionError();
      }
      next_hash:
      for (final String hash : HASHES) {
        int[] lengths = MESSAGE_LENGTHS;
        if (hash.equals("NONE")) {
          switch (base) {
            case "RSA":
              // RSA with NONE is not supported, as RSA padding requires that the hash be known
              continue next_hash;
            case "ECDSA":
              // Similarly, ECDSA raw messages are truncated at the modulus size (384 bits in our
              // case -
              // so 48 bytes).
              lengths = new int[] {0, 1, 16, 32, 33, 47, 48, 49, 50};
              break;
          }
        }

        for (final int length : lengths) {
          String algorithm = String.format("%swith%s", hash, base);
          paramsList.add(new TestParams(base, algorithm, length, false, false, currentPair, null));
          paramsList.add(new TestParams(base, algorithm, length, true, false, currentPair, null));
          paramsList.add(new TestParams(base, algorithm, length, false, true, currentPair, null));
          paramsList.add(new TestParams(base, algorithm, length, true, true, currentPair, null));
          // These new algorithms were only added in 1.3.0
          if (versionCompare("1.3.0", NATIVE_PROVIDER) <= 0) {
            if (base.equals("ECDSA") && !hash.equals("NONE")) {
              algorithm = algorithm + "inP1363Format";
              paramsList.add(
                  new TestParams(base, algorithm, length, false, false, currentPair, null));
              paramsList.add(
                  new TestParams(base, algorithm, length, true, false, currentPair, null));
              paramsList.add(
                  new TestParams(base, algorithm, length, false, true, currentPair, null));
              paramsList.add(
                  new TestParams(base, algorithm, length, true, true, currentPair, null));
            }
          }

          // RSASSA-PSS support added in 2.0, skip PSS validation for older versions
          if (base.equals("RSA") && versionCompare("2.0.0", NATIVE_PROVIDER) <= 0) {
            algorithm = "RSASSA-PSS";
            final List<String> paddingHashes = new ArrayList<>(HASHES);
            assertFalse(paddingHashes.contains(null));
            paddingHashes.remove("NONE"); // we don't support null/NONE hashes for PSS
            paddingHashes.replaceAll(h -> h.replace("SHA", "SHA-")); // SunJCE needs the '-'
            assertFalse("NONE".equals(hash)); // we don't support null/NONE hashes for PSS
            final String pssHash = hash.replace("SHA", "SHA-"); // SunJCE needs the '-'
            for (final String mgfHash : paddingHashes) {
              final int[] saltLens = {
                0, // salt len can be 0, but not less
                20, // 20 is the default for PSSParameterSpec
                MessageDigest.getInstance(pssHash).getDigestLength(),
              };
              for (final int saltLen : saltLens) {
                final AlgorithmParameterSpec paramSpec =
                    new PSSParameterSpec(
                        pssHash, "MGF1", new MGF1ParameterSpec(mgfHash), saltLen, 1);
                paramsList.add(
                    new TestParams(base, algorithm, length, false, false, currentPair, paramSpec));
                paramsList.add(
                    new TestParams(base, algorithm, length, true, false, currentPair, paramSpec));
                paramsList.add(
                    new TestParams(base, algorithm, length, false, true, currentPair, paramSpec));
                paramsList.add(
                    new TestParams(base, algorithm, length, true, true, currentPair, paramSpec));
              }
            }
          }
        }
      }
    }

    return paramsList;
  }

  public static Stream<TestParams> params() {
    return byteBufferParams().filter(TestParams::goodForArraysAndByteBuffers);
  }
  /** Test cases for ByteBuffer related tests. */
  public static Stream<TestParams> byteBufferParams() {
    try {
      return getParams().stream().map(TestParams::reset);
    } catch (GeneralSecurityException e) {
      fail(e);
      return null; // unreachable, needed to appease compiler
    }
  }

  @ParameterizedTest
  @MethodSource("params")
  public void exceptionCausesReset(TestParams params) throws GeneralSecurityException {
    final byte[] shortArray = new byte[2];
    params.signer.update(params.message);
    assertThrows(SignatureException.class, () -> params.signer.sign(new byte[1], 0, 1));

    // The above should reset the signature.
    params.signer.update(params.message);
    final byte[] goodSignature = params.signer.sign();
    params.verifier.update(params.message);
    assertTrue(params.verifier.verify(goodSignature));

    // Now, have verification fail
    params.verifier.update(params.message);
    assertThrows(SignatureException.class, () -> params.verifier.verify(shortArray));

    // The above should reset state
    params.verifier.update(params.message);
    assertTrue(params.verifier.verify(goodSignature));
  }

  @ParameterizedTest
  @MethodSource("params")
  public void signSinglePass(TestParams params) throws GeneralSecurityException {
    params.signer.update(params.message);
    params.jceVerifier.update(params.message);
    assertTrue(params.jceVerifier.verify(params.signer.sign()));
  }

  @ParameterizedTest
  @MethodSource("params")
  public void signSingleByte(TestParams params) throws GeneralSecurityException {
    for (final byte b : params.message) {
      params.signer.update(b);
    }
    params.jceVerifier.update(params.message);
    assertTrue(params.jceVerifier.verify(params.signer.sign()));
  }

  @ParameterizedTest
  @MethodSource("params")
  public void signSubArray(TestParams params) throws GeneralSecurityException {
    for (final int length : LENGTHS) {
      if (length > params.message.length) {
        break;
      }
      for (int x = 0; x < params.message.length; x += length) {
        final int len = x + length > params.message.length ? params.message.length - x : length;
        params.signer.update(params.message, x, len);
      }
      params.jceVerifier.update(params.message);
      assertTrue(params.jceVerifier.verify(params.signer.sign()), Integer.toString(length));
    }
  }

  @ParameterizedTest
  @MethodSource("params")
  public void signSingleByteBufferWrap(TestParams params) throws GeneralSecurityException {
    testSingleByteBuffer(params, true, applyParameters(params, (ByteBuffer.wrap(params.message))));
  }

  @ParameterizedTest
  @MethodSource("byteBufferParams")
  public void signSubByteBufferWrap(TestParams params) throws GeneralSecurityException {
    testSubByteBuffer(
        params,
        true,
        (position, length) ->
            applyParameters(params, ByteBuffer.wrap(params.message, position, length)));
  }

  @ParameterizedTest
  @MethodSource("byteBufferParams")
  public void signSingleByteBuffer(TestParams params) throws GeneralSecurityException {
    final ByteBuffer bbuff = ByteBuffer.allocate(params.message.length);
    bbuff.put(params.message);
    bbuff.flip();
    testSingleByteBuffer(params, true, applyParameters(params, bbuff));
  }

  @ParameterizedTest
  @MethodSource("byteBufferParams")
  public void signSubByteBuffer(TestParams params) throws GeneralSecurityException {
    final ByteBuffer bbuff = ByteBuffer.allocate(params.message.length);
    testSubByteBuffer(params, true, new BufferSplitter(params, bbuff));
  }

  @ParameterizedTest
  @MethodSource("byteBufferParams")
  public void signSingleByteBufferDirect(TestParams params) throws GeneralSecurityException {
    final ByteBuffer bbuff = ByteBuffer.allocateDirect(params.message.length);
    bbuff.put(params.message);
    bbuff.flip();
    testSingleByteBuffer(params, true, applyParameters(params, bbuff));
  }

  @ParameterizedTest
  @MethodSource("byteBufferParams")
  public void signSubByteBufferDirect(TestParams params) throws GeneralSecurityException {
    final ByteBuffer bbuff = ByteBuffer.allocateDirect(params.message.length);
    testSubByteBuffer(params, true, new BufferSplitter(params, bbuff));
  }

  @ParameterizedTest
  @MethodSource("params")
  public void verifySinglePass(TestParams params) throws GeneralSecurityException {
    params.verifier.update(params.message);

    assertTrue(params.verifier.verify(params.goodSignature));
  }

  @ParameterizedTest
  @MethodSource("params")
  public void verifyBadSignature(TestParams params) throws GeneralSecurityException {
    params.verifier.update(params.message);
    byte[] badSignature = params.goodSignature.clone();
    badSignature[badSignature.length - 1]++;
    try {
      assertFalse(params.verifier.verify(badSignature));
    } catch (final SignatureException ex) {
      if (params.algorithm.contains("RSA")) {
        // RSA is not allowed to fail with an exception
        throw ex;
      }
    }
  }

  @ParameterizedTest
  @MethodSource("params")
  public void verifyTruncatedSignature(TestParams params) throws GeneralSecurityException {
    params.verifier.update(params.message);
    final byte[] badSignature =
        Arrays.copyOf(params.goodSignature, params.goodSignature.length - 1);
    // Truncated signatures always throw now.
    assertThrows(SignatureException.class, () -> params.verifier.verify(badSignature));
  }

  @ParameterizedTest
  @MethodSource("params")
  public void verifyExtendedSignature(TestParams params) throws GeneralSecurityException {
    params.verifier.update(params.message);
    final byte[] badSignature =
        Arrays.copyOf(params.goodSignature, params.goodSignature.length + 1);
    // Extended signatures always throw now.
    assertThrows(SignatureException.class, () -> params.verifier.verify(badSignature));
  }

  // Modification of body of the message only works
  // if the message is not empty
  private static Stream<TestParams> wrongMessageParams() {
    return params().filter(p -> p.length > 0);
  }

  @ParameterizedTest
  @MethodSource("wrongMessageParams")
  public void verifyWrongMessage(TestParams params) throws GeneralSecurityException {
    byte[] msgCopy = params.message.clone();
    msgCopy[0]++;
    params.verifier.update(msgCopy);
    assertFalse(params.verifier.verify(params.goodSignature));
  }

  // If we're already beyond the message size limit, we expect truncation to be ignored
  private static Stream<TestParams> verifyTruncatedMessageParams() {
    return params().filter(p -> p.length > 0 && p.length <= p.getMessageSizeLimit());
  }

  @ParameterizedTest
  @MethodSource("verifyTruncatedMessageParams")
  public void verifyTruncatedMessage(TestParams params) throws Exception {
    params.verifier.update(Arrays.copyOf(params.message, params.message.length - 1));
    assertFalse(params.verifier.verify(params.goodSignature));
  }

  // If we're just at the message size limit, any additional bytes will be ignored
  private static Stream<TestParams> verifyExtendedMessageParams() {
    return params().filter(p -> (p.length + 1) <= p.getMessageSizeLimit());
  }

  @ParameterizedTest
  @MethodSource("verifyExtendedMessageParams")
  public void verifyExtendedMessage(TestParams params) throws Exception {
    params.verifier.update(params.message);
    params.verifier.update((byte) 0x44);
    assertFalse(params.verifier.verify(params.goodSignature));
  }

  @ParameterizedTest
  @MethodSource("params")
  public void verifySingleByte(TestParams params) throws GeneralSecurityException {
    for (final byte b : params.message) {
      params.verifier.update(b);
    }

    assertTrue(params.verifier.verify(params.goodSignature));
  }

  @ParameterizedTest
  @MethodSource("params")
  public void verifySubArray(TestParams params) throws GeneralSecurityException {
    for (final int length : LENGTHS) {
      if (length > params.message.length) {
        break;
      }
      for (int x = 0; x < params.message.length; x += length) {
        final int len = x + length > params.message.length ? params.message.length - x : length;
        params.verifier.update(params.message, x, len);
      }

      assertTrue(params.verifier.verify(params.goodSignature), Integer.toString(length));
    }
  }

  @ParameterizedTest
  @MethodSource("params")
  public void verifySignatureInLargerArray(TestParams params) throws SignatureException {
    final int offset = 7;
    final int length = params.goodSignature.length;
    final byte[] paddedSignature = new byte[3 * offset + length];
    // Ensure the padding isn't just 0s which might not trigger exceptions
    Arrays.fill(paddedSignature, (byte) 0x20);
    System.arraycopy(params.goodSignature, 0, paddedSignature, offset, length);

    params.verifier.update(params.message);
    assertTrue(params.verifier.verify(paddedSignature, offset, length));
  }

  @ParameterizedTest
  @MethodSource("byteBufferParams")
  public void verifySingleByteBufferWrap(TestParams params) throws GeneralSecurityException {
    testSingleByteBuffer(params, false, applyParameters(params, ByteBuffer.wrap(params.message)));
  }

  @ParameterizedTest
  @MethodSource("byteBufferParams")
  public void verifySubByteBufferWrap(TestParams params) throws GeneralSecurityException {
    testSubByteBuffer(
        params,
        false,
        (position, length) ->
            applyParameters(params, ByteBuffer.wrap(params.message, position, length)));
  }

  @ParameterizedTest
  @MethodSource("byteBufferParams")
  public void verifySingleByteBuffer(TestParams params) throws GeneralSecurityException {
    final ByteBuffer bbuff = ByteBuffer.allocate(params.message.length);
    bbuff.put(params.message);
    bbuff.flip();
    testSingleByteBuffer(params, false, bbuff);
  }

  @ParameterizedTest
  @MethodSource("byteBufferParams")
  public void verifySubByteBuffer(TestParams params) throws GeneralSecurityException {
    final ByteBuffer bbuff = ByteBuffer.allocate(params.message.length);
    testSubByteBuffer(params, false, new BufferSplitter(params, bbuff));
  }

  @ParameterizedTest
  @MethodSource("byteBufferParams")
  public void verifySingleByteBufferDirect(TestParams params) throws GeneralSecurityException {
    final ByteBuffer bbuff = ByteBuffer.allocate(params.message.length);
    bbuff.put(params.message);
    bbuff.flip();
    testSingleByteBuffer(params, false, applyParameters(params, bbuff));
  }

  @ParameterizedTest
  @MethodSource("byteBufferParams")
  public void verifySubByteBufferDirect(TestParams params) throws GeneralSecurityException {
    final ByteBuffer bbuff = ByteBuffer.allocateDirect(params.message.length);
    testSubByteBuffer(params, false, new BufferSplitter(params, bbuff));
  }

  @ParameterizedTest
  @MethodSource("byteBufferParams")
  public void nullKeyYieldsInvalidKeyException(TestParams params) {
    assertThrows(InvalidKeyException.class, () -> params.signer.initSign(null));
    assertThrows(InvalidKeyException.class, () -> params.verifier.initVerify((PublicKey) null));
  }

  private static Stream<TestParams> corruptedSignatureParams() {
    // Does not apply to RSA algorithms or P1363Format
    return params()
        .filter(p -> !p.algorithm.contains("RSA") && !p.algorithm.contains("inP1363Format"));
  }

  @ParameterizedTest
  @MethodSource("corruptedSignatureParams")
  public void corruptedSignatureYieldsException(TestParams params) {
    // JCA/JCE standards require that we try to throw an exception if the underlying signature is
    // "corrupt" and not
    // just invalid.
    byte[] badSignature = params.goodSignature.clone();
    for (int x = 0; x < badSignature.length; x++) {
      badSignature[x] ^= 0x5c; // Arbitrary value to twiddle the bits
    }

    assertThrows(SignatureException.class, () -> params.verifier.verify(badSignature));
  }

  private void testSingleByteBuffer(TestParams params, boolean signMode, final ByteBuffer buff)
      throws GeneralSecurityException {
    final int oldLimit = buff.limit();
    if (signMode) {
      params.signer.update(buff);
      params.jceVerifier.update(params.message);
      assertTrue(params.jceVerifier.verify(params.signer.sign()));
    } else {
      params.verifier.update(buff);
      assertTrue(params.verifier.verify(params.goodSignature));
    }
    assertEquals(buff.limit(), buff.position(), "Buffer position isn't advanced.");
    assertEquals(oldLimit, buff.limit(), "Buffer limit incorrectly modified.");
  }

  private void testSubByteBuffer(
      TestParams params, boolean signMode, BiFunction<Integer, Integer, ByteBuffer> provider)
      throws GeneralSecurityException {
    final Signature sig = signMode ? params.signer : params.verifier;
    for (final int length : LENGTHS) {
      if (length > params.message.length) {
        break;
      }
      for (int x = 0; x < params.message.length; x += length) {
        final int len = x + length > params.message.length ? params.message.length - x : length;
        final ByteBuffer buff = provider.apply(x, len);
        final int oldLimit = buff.limit();
        sig.update(buff);
        assertEquals(
            buff.limit(),
            buff.position(),
            String.format(
                "Buffer position isn't advanced for position %d and length %d", x, length));
        assertEquals(
            oldLimit,
            buff.limit(),
            String.format(
                "Buffer position is incorrectly modified for position %d and length %d",
                x, length));
      }
      if (signMode) {
        params.jceVerifier.update(params.message);
        assertTrue(
            params.jceVerifier.verify(params.signer.sign()),
            String.format("Signing fails for length %d", length));
      } else {
        assertTrue(
            params.verifier.verify(params.goodSignature),
            String.format("Verification fails for length %d", length));
      }
    }
  }

  private final class BufferSplitter implements BiFunction<Integer, Integer, ByteBuffer> {
    final ByteBuffer baseBuffer_;
    final TestParams params_;

    public BufferSplitter(TestParams params, ByteBuffer baseBuffer) {
      baseBuffer_ = baseBuffer;
      this.params_ = params;
    }

    @Override
    public ByteBuffer apply(final Integer position, final Integer length) {
      baseBuffer_.position(position);
      baseBuffer_.limit(baseBuffer_.position() + length);
      baseBuffer_.put(params_.message, position, length);
      baseBuffer_.position(position);
      return applyParameters(params_, baseBuffer_);
    }
  }

  private ByteBuffer applyParameters(TestParams params, final ByteBuffer buff) {
    ByteBuffer result = buff;
    if (params.readOnly) {
      result = result.asReadOnlyBuffer();
    }
    if (params.slice) {
      result = result.slice();
    }
    return result;
  }
}
