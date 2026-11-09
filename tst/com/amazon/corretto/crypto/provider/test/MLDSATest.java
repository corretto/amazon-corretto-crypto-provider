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
import com.amazon.corretto.crypto.utils.MlDsaUtils;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
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

  // Encoded public key length uniquely identifies the ML-DSA parameter set.
  private static int publicKeyLength(String paramSet) throws Exception {
    return KeyPairGenerator.getInstance(paramSet, NATIVE_PROVIDER)
        .generateKeyPair()
        .getPublic()
        .getEncoded()
        .length;
  }

  @Test
  public void testGenericKeyPairGeneratorDefaultsTo44() throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA", NATIVE_PROVIDER);
    assertEquals(
        publicKeyLength("ML-DSA-44"), keyGen.generateKeyPair().getPublic().getEncoded().length);
  }

  @ParameterizedTest
  @ValueSource(strings = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
  public void testGenericKeyPairGeneratorIsParameterSetSelectable(String paramSet)
      throws Exception {
    TestUtil.assumeMinimumJavaVersion(11);
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA", NATIVE_PROVIDER);
    keyGen.initialize(TestUtil.namedParameterSpec(paramSet));
    assertEquals(
        publicKeyLength(paramSet), keyGen.generateKeyPair().getPublic().getEncoded().length);
    // Lower-case names are accepted too, matching the JCA's case-insensitive algorithm names.
    keyGen.initialize(TestUtil.namedParameterSpec(paramSet.toLowerCase()), new SecureRandom());
    assertEquals(
        publicKeyLength(paramSet), keyGen.generateKeyPair().getPublic().getEncoded().length);
  }

  @Test
  public void testGenericKeyPairGeneratorRejectsInvalidSpecs() throws Exception {
    TestUtil.assumeMinimumJavaVersion(11);
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA", NATIVE_PROVIDER);
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> keyGen.initialize(TestUtil.namedParameterSpec("ML-DSA-99")));
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> keyGen.initialize(TestUtil.namedParameterSpec("ML-KEM-768")));
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> keyGen.initialize((AlgorithmParameterSpec) null));
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> keyGen.initialize(new AlgorithmParameterSpec() {}));
  }

  // A parameter-set-specific generator accepts a spec naming its own set and rejects any other, so
  // it never silently produces a key of the wrong parameter set.
  @ParameterizedTest
  @ValueSource(strings = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
  public void testSpecificKeyPairGeneratorsRemainStrict(String paramSet) throws Exception {
    TestUtil.assumeMinimumJavaVersion(11);
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance(paramSet, NATIVE_PROVIDER);
    keyGen.initialize(TestUtil.namedParameterSpec(paramSet));
    assertEquals(
        publicKeyLength(paramSet), keyGen.generateKeyPair().getPublic().getEncoded().length);
    for (String other : new String[] {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"}) {
      if (!other.equals(paramSet)) {
        assertThrows(
            InvalidAlgorithmParameterException.class,
            () -> keyGen.initialize(TestUtil.namedParameterSpec(other)));
      }
    }
  }

  // BouncyCastle names ML-DSA parameter sets with its own MLDSAParameterSpec rather than
  // NamedParameterSpec. Both generators accept it, and the strict services still reject a spec
  // naming a different (or HashML-DSA) parameter set.
  @ParameterizedTest
  @ValueSource(strings = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
  public void testKeyPairGeneratorAcceptsBouncyCastleSpec(String paramSet) throws Exception {
    MLDSAParameterSpec bcSpec = MLDSAParameterSpec.fromName(paramSet);

    KeyPairGenerator generic = KeyPairGenerator.getInstance("ML-DSA", NATIVE_PROVIDER);
    generic.initialize(bcSpec);
    assertEquals(
        publicKeyLength(paramSet), generic.generateKeyPair().getPublic().getEncoded().length);

    KeyPairGenerator specific = KeyPairGenerator.getInstance(paramSet, NATIVE_PROVIDER);
    specific.initialize(bcSpec);
    assertEquals(
        publicKeyLength(paramSet), specific.generateKeyPair().getPublic().getEncoded().length);

    assertThrows(
        InvalidAlgorithmParameterException.class,
        () ->
            KeyPairGenerator.getInstance("ML-DSA-65", NATIVE_PROVIDER)
                .initialize(MLDSAParameterSpec.ml_dsa_44));
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> generic.initialize(MLDSAParameterSpec.ml_dsa_44_with_sha512));
  }

  // The KeyPairGenerator contract requires InvalidParameterException for an unsupported key size.
  @ParameterizedTest
  @ValueSource(strings = {"ML-DSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
  public void testKeySizeInitializationRejected(String algo) throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algo, NATIVE_PROVIDER);
    assertThrows(InvalidParameterException.class, () -> keyGen.initialize(0));
    assertThrows(InvalidParameterException.class, () -> keyGen.initialize(-2, new SecureRandom()));
    assertThrows(InvalidParameterException.class, () -> keyGen.initialize(2048));
    // -1 is accepted, and the generator still produces keys.
    keyGen.initialize(-1, new SecureRandom());
    assertNotNull(keyGen.generateKeyPair());
  }

  // Reads getParams() reflectively and returns the NamedParameterSpec's name. On JDK 22+ it is
  // called
  // through the public java.security.AsymmetricKey interface, exactly as the JDK's SignatureUtil
  // does. Older JDKs have no such interface; there the method is declared on ACCP's package-private
  // key class, which reflection only lets this test call after setAccessible.
  private static String paramsName(java.security.Key key) throws Exception {
    java.lang.reflect.Method getParams;
    try {
      getParams = Class.forName("java.security.AsymmetricKey").getMethod("getParams");
    } catch (ClassNotFoundException e) {
      getParams = key.getClass().getMethod("getParams");
      getParams.setAccessible(true);
    }
    Object spec = getParams.invoke(key);
    assertNotNull(spec, "getParams() must return a NamedParameterSpec on JDK 11+");
    assertEquals("java.security.spec.NamedParameterSpec", spec.getClass().getName());
    return (String) spec.getClass().getMethod("getName").invoke(spec);
  }

  // jarsigner/keytool (SignatureUtil.fromSignature) derive the per-parameter-set OID from
  // key.getParams(); without it signing fails with "Cannot derive AlgorithmIdentifier".
  @ParameterizedTest
  @ValueSource(strings = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
  public void testKeysReportParameterSet(String paramSet) throws Exception {
    TestUtil.assumeMinimumJavaVersion(11);
    KeyPair pair = KeyPairGenerator.getInstance(paramSet, NATIVE_PROVIDER).generateKeyPair();
    assertEquals(paramSet, paramsName(pair.getPrivate()));
    assertEquals(paramSet, paramsName(pair.getPublic()));

    // Keys rebuilt through the KeyFactory report it too.
    KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA", NATIVE_PROVIDER);
    assertEquals(
        paramSet,
        paramsName(
            keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pair.getPrivate().getEncoded()))));
    assertEquals(
        paramSet,
        paramsName(
            keyFactory.generatePublic(new X509EncodedKeySpec(pair.getPublic().getEncoded()))));

    // So do keys from the generic generator once a parameter set is selected.
    KeyPairGenerator generic = KeyPairGenerator.getInstance("ML-DSA", NATIVE_PROVIDER);
    generic.initialize(TestUtil.namedParameterSpec(paramSet));
    assertEquals(paramSet, paramsName(generic.generateKeyPair().getPrivate()));
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

  // jtreg SeedOrExpanded: a key returned by KeyFactory.translateKey is used to sign and then
  // re-encoded. It must survive the Signature operation rather than being released as ephemeral.
  @Test
  public void testTranslatedKeyRemainsUsableAfterSigning() throws Exception {
    KeyPair bcPair =
        KeyPairGenerator.getInstance("ML-DSA-65", TestUtil.BC_PROVIDER).generateKeyPair();
    KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA", NATIVE_PROVIDER);
    PrivateKey translated = (PrivateKey) keyFactory.translateKey(bcPair.getPrivate());

    Signature signer = Signature.getInstance("ML-DSA", NATIVE_PROVIDER);
    for (int i = 0; i < 2; i++) {
      signer.initSign(translated);
      signer.update(new byte[] {1, 2, 3});
      signer.sign();
    }

    assertNotNull(translated.getEncoded());
    // Re-parsing ACCP's encoding yields a key that still signs.
    PrivateKey reparsed =
        keyFactory.generatePrivate(new PKCS8EncodedKeySpec(translated.getEncoded()));
    signer.initSign(reparsed);
    signer.update(new byte[] {4, 5, 6});
    assertNotNull(signer.sign());
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
    // keys in "seed" form.
    KeyFactory bcKf = KeyFactory.getInstance("ML-DSA", TestUtil.BC_PROVIDER);
    KeyPair nativePair =
        KeyPairGenerator.getInstance("ML-DSA-44", NATIVE_PROVIDER).generateKeyPair();
    PublicKey nativePub = nativePair.getPublic();
    PrivateKey nativePriv = nativePair.getPrivate();
    PublicKey bcPub = bcKf.generatePublic(new X509EncodedKeySpec(nativePub.getEncoded()));
    PrivateKey bcPriv = bcKf.generatePrivate(new PKCS8EncodedKeySpec(nativePriv.getEncoded()));
    TestUtil.assertArraysHexEquals(bcPub.getEncoded(), nativePub.getEncoded());
    assertEquals(bcPriv.getEncoded().length, nativePriv.getEncoded().length);
    TestUtil.assertArraysHexEquals(bcPriv.getEncoded(), nativePriv.getEncoded());

    nativePair = KeyPairGenerator.getInstance("ML-DSA-65", NATIVE_PROVIDER).generateKeyPair();
    nativePub = nativePair.getPublic();
    nativePriv = nativePair.getPrivate();
    bcPub = bcKf.generatePublic(new X509EncodedKeySpec(nativePub.getEncoded()));
    bcPriv = bcKf.generatePrivate(new PKCS8EncodedKeySpec(nativePriv.getEncoded()));
    TestUtil.assertArraysHexEquals(bcPub.getEncoded(), nativePub.getEncoded());
    assertEquals(bcPriv.getEncoded().length, nativePriv.getEncoded().length);
    TestUtil.assertArraysHexEquals(bcPriv.getEncoded(), nativePriv.getEncoded());

    nativePair = KeyPairGenerator.getInstance("ML-DSA-87", NATIVE_PROVIDER).generateKeyPair();
    nativePub = nativePair.getPublic();
    nativePriv = nativePair.getPrivate();
    bcPub = bcKf.generatePublic(new X509EncodedKeySpec(nativePub.getEncoded()));
    bcPriv = bcKf.generatePrivate(new PKCS8EncodedKeySpec(nativePriv.getEncoded()));
    TestUtil.assertArraysHexEquals(bcPub.getEncoded(), nativePub.getEncoded());
    TestUtil.assertArraysHexEquals(bcPriv.getEncoded(), nativePriv.getEncoded());

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
    byte[] mu = MlDsaUtils.computeMu(pub, message);
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

  // initialize(NamedParameterSpec) matches SUN: the generic ML-DSA generator accepts a spec
  // selecting any parameter set; a parameter-set-specific generator rejects a spec naming another.
  @Test
  public void testNamedParameterSpecInitializationMatchesSun() throws Exception {
    TestUtil.assumeMinimumJavaVersion(24);
    AlgorithmParameterSpec mlDsa87 = TestUtil.namedParameterSpec("ML-DSA-87");

    // ACCP: the generic generator selects ML-DSA-87
    KeyPairGenerator accpGeneric = KeyPairGenerator.getInstance("ML-DSA", NATIVE_PROVIDER);
    accpGeneric.initialize(mlDsa87);
    KeyPair accpPair = accpGeneric.generateKeyPair();

    // SUN: the generic generator selects ML-DSA-87
    KeyPairGenerator sunGeneric = KeyPairGenerator.getInstance("ML-DSA", "SUN");
    sunGeneric.initialize(mlDsa87);
    KeyPair sunPair = sunGeneric.generateKeyPair();

    assertEquals(sunPair.getPublic().getEncoded().length, accpPair.getPublic().getEncoded().length);

    // ACCP: the ML-DSA-44 generator rejects a spec naming ML-DSA-87, and a null spec
    KeyPairGenerator accp44 = KeyPairGenerator.getInstance("ML-DSA-44", NATIVE_PROVIDER);
    assertThrows(InvalidAlgorithmParameterException.class, () -> accp44.initialize(mlDsa87));
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> accp44.initialize((AlgorithmParameterSpec) null));

    // SUN: the ML-DSA-44 generator rejects a spec naming ML-DSA-87, and a null spec
    KeyPairGenerator sun44 = KeyPairGenerator.getInstance("ML-DSA-44", "SUN");
    assertThrows(InvalidAlgorithmParameterException.class, () -> sun44.initialize(mlDsa87));
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> sun44.initialize((AlgorithmParameterSpec) null));
  }

  // initialize(int) matches SUN: unsupported key sizes throw InvalidParameterException, but -1
  // (the JDK's "keep the parameter set, use this SecureRandom"; jtreg SeedOrExpanded) is allowed.
  @Test
  public void testKeySizeInitializationMatchesSun() throws Exception {
    // TODO: lift the JDK 24+ restriction once OpenJDK backports ML-DSA to its LTS releases:
    // https://blogs.oracle.com/java/post-quantum-cryptography-in-long-term-support-jdk-releases
    TestUtil.assumeMinimumJavaVersion(24);
    KeyPairGenerator accpGen = KeyPairGenerator.getInstance("ML-DSA-65", NATIVE_PROVIDER);
    KeyPairGenerator sunGen = KeyPairGenerator.getInstance("ML-DSA-65", "SUN");

    // ACCP: unsupported key sizes are rejected
    assertThrows(InvalidParameterException.class, () -> accpGen.initialize(0));
    assertThrows(
        InvalidParameterException.class, () -> accpGen.initialize(2048, new SecureRandom()));

    // SUN: unsupported key sizes are rejected
    assertThrows(InvalidParameterException.class, () -> sunGen.initialize(0));
    assertThrows(
        InvalidParameterException.class, () -> sunGen.initialize(2048, new SecureRandom()));

    // ACCP: -1 is accepted and keeps the parameter set
    accpGen.initialize(-1, new SecureRandom());
    KeyPair accpPair = accpGen.generateKeyPair();

    // SUN: -1 is accepted and keeps the parameter set
    sunGen.initialize(-1, new SecureRandom());
    KeyPair sunPair = sunGen.generateKeyPair();

    assertEquals(sunPair.getPublic().getEncoded().length, accpPair.getPublic().getEncoded().length);
  }

  // KeyFactory null handling matches SUN: a null spec throws InvalidKeySpecException and a null
  // key throws InvalidKeyException, never NullPointerException.
  @Test
  public void testKeyFactoryNullInputsMatchSun() throws Exception {
    TestUtil.assumeMinimumJavaVersion(24);

    // ACCP
    KeyFactory accpKf = KeyFactory.getInstance("ML-DSA", NATIVE_PROVIDER);
    assertThrows(InvalidKeySpecException.class, () -> accpKf.generatePublic(null));
    assertThrows(InvalidKeySpecException.class, () -> accpKf.generatePrivate(null));
    assertThrows(InvalidKeyException.class, () -> accpKf.translateKey(null));

    // SUN
    KeyFactory sunKf = KeyFactory.getInstance("ML-DSA", "SUN");
    assertThrows(InvalidKeySpecException.class, () -> sunKf.generatePublic(null));
    assertThrows(InvalidKeySpecException.class, () -> sunKf.generatePrivate(null));
    assertThrows(InvalidKeyException.class, () -> sunKf.translateKey(null));
  }

  // jtreg SeedOrExpanded, compared with SUN: a key returned by KeyFactory.translateKey stays usable
  // after the Signature that signed with it is re-initialized to verify with a different key.
  @Test
  public void testTranslatedKeySurvivesSignatureReinitMatchesSun() throws Exception {
    TestUtil.assumeMinimumJavaVersion(24);
    KeyPair bcPair =
        KeyPairGenerator.getInstance("ML-DSA-65", TestUtil.BC_PROVIDER).generateKeyPair();
    byte[] message = {1, 2, 3};

    // ACCP: sign, verify with the same Signature, then reuse the translated key
    PrivateKey accpKey =
        (PrivateKey)
            KeyFactory.getInstance("ML-DSA", NATIVE_PROVIDER).translateKey(bcPair.getPrivate());
    Signature accpSig = Signature.getInstance("ML-DSA", NATIVE_PROVIDER);
    accpSig.initSign(accpKey);
    accpSig.update(message);
    byte[] accpSignature = accpSig.sign();
    accpSig.initVerify(bcPair.getPublic());
    accpSig.update(message);
    assertTrue(accpSig.verify(accpSignature));
    assertNotNull(accpKey.getEncoded());

    // SUN: sign, verify with the same Signature, then reuse the translated key
    PrivateKey sunKey =
        (PrivateKey) KeyFactory.getInstance("ML-DSA", "SUN").translateKey(bcPair.getPrivate());
    Signature sunSig = Signature.getInstance("ML-DSA", "SUN");
    sunSig.initSign(sunKey);
    sunSig.update(message);
    byte[] sunSignature = sunSig.sign();
    sunSig.initVerify(bcPair.getPublic());
    sunSig.update(message);
    assertTrue(sunSig.verify(sunSignature));
    assertNotNull(sunKey.getEncoded());
  }

  // getParams() matches SUN on generated keys and on a key decoded from SUN's encoding. The JDK
  // uses it to pick the signature OID (keytool/jarsigner via SignatureUtil.fromSignature).
  @ParameterizedTest
  @ValueSource(strings = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
  public void testGetParamsMatchesSun(String paramSet) throws Exception {
    TestUtil.assumeMinimumJavaVersion(24);

    // ACCP
    KeyPair accpPair = KeyPairGenerator.getInstance(paramSet, NATIVE_PROVIDER).generateKeyPair();

    // SUN
    KeyPair sunPair = KeyPairGenerator.getInstance(paramSet, "SUN").generateKeyPair();

    assertEquals(paramsName(sunPair.getPublic()), paramsName(accpPair.getPublic()));
    assertEquals(paramsName(sunPair.getPrivate()), paramsName(accpPair.getPrivate()));

    // ACCP decodes SUN's public key and reports the same parameter set as SUN
    PublicKey decoded =
        KeyFactory.getInstance("ML-DSA", NATIVE_PROVIDER)
            .generatePublic(new X509EncodedKeySpec(sunPair.getPublic().getEncoded()));
    assertEquals(paramsName(sunPair.getPublic()), paramsName(decoded));
  }
}
