// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import com.amazon.corretto.crypto.provider.RuntimeCryptoException;
import com.amazon.corretto.crypto.utils.MlKemUtils;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.interfaces.MLKEMPrivateKey;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.junit.jupiter.api.Test;
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
public class MlKemTest {
  private static final AmazonCorrettoCryptoProvider NATIVE_PROVIDER =
      AmazonCorrettoCryptoProvider.INSTANCE;
  private static final int SHARED_SECRET_SIZE = 32;
  private static final String[] ML_KEM_PARAM_SETS = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"};
  // An OID under an unassigned private-enterprise arc, so no provider maps it to an algorithm.
  private static final String UNASSIGNED_OID = "1.3.6.1.4.1.99999.1";
  // Identifying tag bytes of the three ML-KEM private-key CHOICEs of RFC 9935 Section 6, as they
  // appear at the start of the privateKey OCTET STRING's contents.
  private static final int CHOICE_TAG_SEED = 0x80; // [0] IMPLICIT OCTET STRING, primitive
  private static final int CHOICE_TAG_EXPANDED = 0x04; // OCTET STRING
  private static final int CHOICE_TAG_BOTH = 0x30; // SEQUENCE { seed, expandedKey }

  private static String[] mlKemParamSets() {
    return ML_KEM_PARAM_SETS;
  }

  private static int getCiphertextSizeForParamSet(String paramSet) throws Throwable {
    Class<?> mlKemParamClass = Class.forName("com.amazon.corretto.crypto.provider.MlKemParameter");
    Object mlKemParam = TestUtil.sneakyInvoke(mlKemParamClass, "fromKemName", paramSet);
    return TestUtil.sneakyInvoke_int(mlKemParam, "getCiphertextSize");
  }

  private static class TestParams {
    private final Provider encapsulatorProv;
    private final Provider decapsulatorProv;
    private final PrivateKey priv;
    private final PublicKey pub;
    private final String parameterSet;

    public TestParams(
        Provider encapsulatorProv,
        Provider decapsulatorProv,
        PrivateKey priv,
        PublicKey pub,
        String parameterSet) {
      this.encapsulatorProv = encapsulatorProv;
      this.decapsulatorProv = decapsulatorProv;
      this.priv = priv;
      this.pub = pub;
      this.parameterSet = parameterSet;
    }

    public String toString() {
      return String.format(
          "encapsulator: %s, decapsulator: %s, parameter set: %s",
          encapsulatorProv.getName(), decapsulatorProv.getName(), parameterSet);
    }
  }

  private static List<TestParams> getParams() throws Exception {
    List<TestParams> params = new ArrayList<TestParams>();
    for (String paramSet : ML_KEM_PARAM_SETS) {
      KeyPair keyPair = KeyPairGenerator.getInstance(paramSet, NATIVE_PROVIDER).generateKeyPair();
      PublicKey nativePub = keyPair.getPublic();
      PrivateKey nativePriv = keyPair.getPrivate();

      Provider nativeProv = NATIVE_PROVIDER;

      params.add(new TestParams(nativeProv, nativeProv, nativePriv, nativePub, paramSet));
    }
    return params;
  }

  @ParameterizedTest
  @MethodSource("getParams")
  public void testKemRoundTrips(TestParams params) throws Exception {
    KEM encapsulatorKem = KEM.getInstance(params.parameterSet, params.encapsulatorProv);
    KEM decapsulatorKem = KEM.getInstance(params.parameterSet, params.decapsulatorProv);

    NamedParameterSpec paramSpec = new NamedParameterSpec(params.parameterSet);

    KEM.Encapsulator encapsulator = encapsulatorKem.newEncapsulator(params.pub, paramSpec, null);
    KEM.Encapsulated encapsulated = encapsulator.encapsulate();

    assertNotNull(encapsulated, "Encapsulated result should not be null");
    assertNotNull(encapsulated.key(), "Shared secret should not be null");
    assertNotNull(encapsulated.encapsulation(), "Ciphertext should not be null");

    SecretKey sharedSecret = encapsulated.key();
    byte[] ciphertext = encapsulated.encapsulation();
    assertEquals(
        SHARED_SECRET_SIZE, sharedSecret.getEncoded().length, "Shared secret should be 32 bytes");

    KEM.Decapsulator decapsulator = decapsulatorKem.newDecapsulator(params.priv, paramSpec);
    SecretKey recoveredSecret = decapsulator.decapsulate(ciphertext);
    assertNotNull(recoveredSecret, "Recovered secret should not be null");
    assertEquals(
        SHARED_SECRET_SIZE,
        recoveredSecret.getEncoded().length,
        "Recovered secret should be 32 bytes");
    assertArrayEquals(
        sharedSecret.getEncoded(),
        recoveredSecret.getEncoded(),
        "Original and recovered secrets should match");
  }

  @ParameterizedTest
  @MethodSource("getParams")
  public void testKemSecretsAreDestroyable(TestParams params) throws Exception {
    KEM encapsulatorKem = KEM.getInstance(params.parameterSet, params.encapsulatorProv);
    KEM decapsulatorKem = KEM.getInstance(params.parameterSet, params.decapsulatorProv);
    NamedParameterSpec paramSpec = new NamedParameterSpec(params.parameterSet);

    KEM.Encapsulator encapsulator = encapsulatorKem.newEncapsulator(params.pub, paramSpec, null);
    KEM.Encapsulated encapsulated = encapsulator.encapsulate();
    KEM.Decapsulator decapsulator = decapsulatorKem.newDecapsulator(params.priv, paramSpec);
    SecretKey recovered = decapsulator.decapsulate(encapsulated.encapsulation());

    for (SecretKey key : new SecretKey[] {encapsulated.key(), recovered}) {
      assertFalse(key.isDestroyed());
      assertNotNull(key.getEncoded());

      key.destroy();

      assertTrue(key.isDestroyed());
      assertThrows(IllegalStateException.class, key::getEncoded);
      assertThrows(IllegalStateException.class, key::getAlgorithm);
    }
  }

  @ParameterizedTest
  @MethodSource("mlKemParamSets")
  public void testKeyGeneration(String paramSet) throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance(paramSet, NATIVE_PROVIDER);
    KeyPair keyPair = keyGen.generateKeyPair();

    assertNotNull(keyPair);
    assertNotNull(keyPair.getPrivate());
    assertNotNull(keyPair.getPublic());

    assertEquals(paramSet, keyPair.getPrivate().getAlgorithm());
    assertEquals(paramSet, keyPair.getPublic().getAlgorithm());
  }

  @ParameterizedTest
  @MethodSource("mlKemParamSets")
  public void testKeyPairGeneratorInitializeAcceptsMatchingSpecIgnoringRandom(String paramSet)
      throws Exception {
    // Mirrors how a JSSE provider (e.g. BCJSSE) drives ACCP: initialize(NamedParameterSpec, random)
    // with a NON-null SecureRandom, then generateKeyPair(). The random is accepted but ignored
    // (AWS-LC always draws from its own DRBG); the produced key matches the requested parameter
    // set.
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance(paramSet, NATIVE_PROVIDER);
    keyGen.initialize(new NamedParameterSpec(paramSet), new SecureRandom());

    KeyPair keyPair = keyGen.generateKeyPair();
    assertNotNull(keyPair);
    assertEquals(paramSet, keyPair.getPublic().getAlgorithm());
    assertEquals(paramSet, keyPair.getPrivate().getAlgorithm());
  }

  @ParameterizedTest
  @MethodSource("mlKemParamSets")
  public void testKeyPairGeneratorGeneratesWithoutInitialize(String paramSet) throws Exception {
    // Each ML-KEM KeyPairGenerator is bound to its parameter set at construction, so
    // generateKeyPair works with no initialize() call at all -- the path a caller that never sets
    // a spec takes.
    KeyPair keyPair = KeyPairGenerator.getInstance(paramSet, NATIVE_PROVIDER).generateKeyPair();
    assertEquals(paramSet, keyPair.getPublic().getAlgorithm());
    assertEquals(paramSet, keyPair.getPrivate().getAlgorithm());
  }

  @Test
  public void testKeyPairGeneratorInitializeRejectsInvalidSpecs() throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-KEM-768", NATIVE_PROVIDER);
    final SecureRandom random = new SecureRandom();

    // A null spec is rejected.
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> keyGen.initialize((AlgorithmParameterSpec) null, random));

    // A NamedParameterSpec naming a different parameter set is rejected, so this generator never
    // silently produces a key of the wrong parameter set.
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> keyGen.initialize(new NamedParameterSpec("ML-KEM-512"), random));

    // A spec that is not a NamedParameterSpec is rejected.
    final AlgorithmParameterSpec notNamed = new AlgorithmParameterSpec() {};
    assertThrows(
        InvalidAlgorithmParameterException.class, () -> keyGen.initialize(notNamed, random));

    // Keysize-based initialization is unsupported for ML-KEM.
    assertThrows(UnsupportedOperationException.class, () -> keyGen.initialize(768, random));
  }

  @Test
  public void testParameterSpecMismatch() throws Exception {

    KeyPair pair768 = KeyPairGenerator.getInstance("ML-KEM-768", NATIVE_PROVIDER).generateKeyPair();
    KEM kem512 = KEM.getInstance("ML-KEM-512", NATIVE_PROVIDER);

    NamedParameterSpec wrongSpec = new NamedParameterSpec("ML-KEM-512");

    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> kem512.newEncapsulator(pair768.getPublic(), wrongSpec, null));
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> kem512.newDecapsulator(pair768.getPrivate(), wrongSpec));
  }

  @Test
  public void testKeyFactorySelfConversion() throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-KEM", NATIVE_PROVIDER);
    KeyPair originalKeyPair = keyGen.generateKeyPair();

    KeyFactory keyFactory = KeyFactory.getInstance("ML-KEM", NATIVE_PROVIDER);

    byte[] publicKeyEncoded = originalKeyPair.getPublic().getEncoded();
    PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyEncoded));
    assertArrayEquals(publicKeyEncoded, publicKey.getEncoded());

    byte[] privateKeyEncoded = originalKeyPair.getPrivate().getEncoded();
    PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyEncoded));
    assertArrayEquals(privateKeyEncoded, privateKey.getEncoded());
  }

  @ParameterizedTest
  @MethodSource("mlKemParamSets")
  public void testPrivateKeyChoicesParse(String paramSet) throws Exception {
    // ACCP parses the seed and expandedKey CHOICEs of RFC 9935 Section 6 in every build. Those
    // are the two mainline AWS-LC implements, and ACCP's regular-FIPS fallover parser exists to
    // stand in for that decoder, so it accepts exactly them and no more (see the both CHOICE in
    // testBothChoiceRejected). AWS-LC-FIPS 3.1.0 decodes neither, so in regular FIPS the fallover
    // parser is what accepts both encodings here. Every assertion is encoding-independent: the
    // two encodings carry the same key material, so each must decapsulate a given ciphertext to
    // the same shared secret.
    KeyPairGenerator bcKeyGen = KeyPairGenerator.getInstance("ML-KEM", TestUtil.BC_PROVIDER);
    bcKeyGen.initialize(TestUtil.getMlKemParamSpec(paramSet));
    KeyPair bcKeyPair = bcKeyGen.generateKeyPair();
    MLKEMPrivateKey bcPriv = (MLKEMPrivateKey) bcKeyPair.getPrivate();

    byte[] seedForm = bcPriv.getPrivateKey(true).getEncoded();
    byte[] expandedForm = bcPriv.getPrivateKey(false).getEncoded();
    // Guard the premise of the test: these really are the two distinct CHOICEs, so a change in what
    // BouncyCastle emits cannot quietly turn this into two copies of the same coverage.
    assertEquals(
        CHOICE_TAG_SEED,
        privateKeyChoiceTag(seedForm),
        paramSet + " getPrivateKey(true) is the seed");
    assertEquals(
        CHOICE_TAG_EXPANDED,
        privateKeyChoiceTag(expandedForm),
        paramSet + " getPrivateKey(false) is the expandedKey");

    KeyFactory accpKf = KeyFactory.getInstance(paramSet, NATIVE_PROVIDER);
    PublicKey accpPub =
        accpKf.generatePublic(new X509EncodedKeySpec(bcKeyPair.getPublic().getEncoded()));

    KEM kem = KEM.getInstance(paramSet, NATIVE_PROVIDER);
    NamedParameterSpec paramSpec = new NamedParameterSpec(paramSet);
    KEM.Encapsulated encapsulated = kem.newEncapsulator(accpPub, paramSpec, null).encapsulate();
    byte[] ciphertext = encapsulated.encapsulation();

    for (byte[] encoding : new byte[][] {seedForm, expandedForm}) {
      PrivateKey parsed = accpKf.generatePrivate(new PKCS8EncodedKeySpec(encoding));
      assertArrayEquals(
          encapsulated.key().getEncoded(),
          kem.newDecapsulator(parsed, paramSpec).decapsulate(ciphertext).getEncoded(),
          paramSet
              + " private key parsed from CHOICE tag 0x"
              + Integer.toHexString(privateKeyChoiceTag(encoding))
              + " must decapsulate to the encapsulated shared secret");
    }

    // Re-encoding a seed-imported key is where the builds diverge, so pin both sides of it:
    // regular FIPS silently widens the seed to the expanded form because AWS-LC-FIPS 3.1.0
    // retains no keygen seed, while every other flavor gives the seed encoding back unchanged.
    // TODO [AWS-LC-FIPS 5.0]: regular FIPS should re-emit the seed once the module retains it.
    byte[] reEncodedSeed = accpKf.generatePrivate(new PKCS8EncodedKeySpec(seedForm)).getEncoded();
    if (NATIVE_PROVIDER.isFips() && !NATIVE_PROVIDER.isExperimentalFips()) {
      assertEquals(
          CHOICE_TAG_EXPANDED,
          privateKeyChoiceTag(reEncodedSeed),
          paramSet + " regular FIPS re-emits a seed-imported private key in expanded form");
      assertArrayEquals(
          expandedForm,
          reEncodedSeed,
          paramSet + " the widened encoding must match BouncyCastle's expandedKey encoding");
    } else {
      assertArrayEquals(
          seedForm, reEncodedSeed, paramSet + " the seed encoding must round-trip unchanged");
    }
  }

  @ParameterizedTest
  @MethodSource("mlKemParamSets")
  public void testBothChoiceRejected(String paramSet) throws Exception {
    // The both CHOICE (SEQUENCE { seed, expandedKey }) is well-formed RFC 9935 Section 6 and is
    // what BouncyCastle's ML-KEM getEncoded() emits by default, but no AWS-LC flavor decodes it,
    // mainline included: kem_priv_decode there still says "Case 3 ... not implemented yet".
    // ACCP's regular-FIPS fallover parser deliberately matches that rejection instead of filling
    // the gap, so that deleting the parser once AWS-LC-FIPS decodes ML-KEM natively cannot
    // silently withdraw support ACCP had advertised. This test pins the rejection so that support
    // can only ever be added on purpose, together with AWS-LC.
    KeyPairGenerator bcKeyGen = KeyPairGenerator.getInstance("ML-KEM", TestUtil.BC_PROVIDER);
    bcKeyGen.initialize(TestUtil.getMlKemParamSpec(paramSet));
    MLKEMPrivateKey bcPriv = (MLKEMPrivateKey) bcKeyGen.generateKeyPair().getPrivate();
    byte[] bothForm = bcPriv.getEncoded();
    assertEquals(
        CHOICE_TAG_BOTH,
        privateKeyChoiceTag(bothForm),
        paramSet + " BouncyCastle getEncoded() is the both SEQUENCE");

    KeyFactory keyFactory = KeyFactory.getInstance(paramSet, NATIVE_PROVIDER);
    assertPrivateKeyRejected(
        keyFactory, paramSet + " BouncyCastle's default both encoding", bothForm);

    // Also reject it when nothing else about the encoding is unusual: same algorithm, same version
    // 0 PrivateKeyInfo shell as the seed and expandedKey encodings ACCP does accept, and a seed and
    // expandedKey that agree with each other. The CHOICE alone is the reason for the rejection.
    ASN1Encodable algorithm = ASN1Sequence.getInstance(bothForm).getObjectAt(1);
    ASN1Sequence both = ASN1Sequence.getInstance(privateKeyChoiceBytes(bothForm));
    byte[] seed = ASN1OctetString.getInstance(both.getObjectAt(0)).getOctets();
    byte[] expanded = ASN1OctetString.getInstance(both.getObjectAt(1)).getOctets();
    assertPrivateKeyRejected(
        keyFactory,
        paramSet + " a self-consistent both CHOICE in a version 0 PrivateKeyInfo",
        pkcs8WithPrivateKeyChoice(algorithm, bothChoice(seed, expanded)));

    // The halves on their own are accepted, so the rejections above are attributable to the CHOICE
    // rather than to this test having mangled the key material or the shell.
    assertNotNull(
        keyFactory.generatePrivate(
            new PKCS8EncodedKeySpec(
                pkcs8WithPrivateKeyChoice(
                    algorithm, new DERTaggedObject(false, 0, new DEROctetString(seed))))),
        paramSet + " the seed half alone must be accepted");
    assertNotNull(
        keyFactory.generatePrivate(
            new PKCS8EncodedKeySpec(
                pkcs8WithPrivateKeyChoice(algorithm, new DEROctetString(expanded)))),
        paramSet + " the expandedKey half alone must be accepted");

    // MlKemUtils.expandPrivateKey parses through the same grammar, so it rejects the both CHOICE
    // too rather than handing the input back unchanged. Note that this is reachable with a stock
    // BouncyCastle key: getAlgorithm() on one is the parameter-set name, so the ML-KEM check in
    // expandPrivateKey passes and the both-encoded getEncoded() reaches the native parser. The
    // rejection is unchecked because expandPrivateKey declares no checked exceptions.
    assertThrows(RuntimeCryptoException.class, () -> MlKemUtils.expandPrivateKey(bcPriv));
  }

  @ParameterizedTest
  @MethodSource("mlKemParamSets")
  public void testImportedPrivateKeyPublicKeyAvailability(String paramSet) throws Throwable {
    // ACCP reconstructs an imported ML-KEM private key the same way mainline AWS-LC's decoder
    // does, one CHOICE at a time, so the two agree per CHOICE in every build: seed derives the
    // whole key pair, while expandedKey sets only the raw secret key (KEM_KEY_set_raw_secret_key)
    // and leaves the public key unpopulated. Encoding the public key of an expandedKey-imported
    // private key therefore fails instead of returning its SPKI. Pinned here so the asymmetry
    // cannot change silently in either direction: closing it in ACCP alone would be a divergence
    // from AWS-LC.
    KeyPairGenerator bcKeyGen = KeyPairGenerator.getInstance("ML-KEM", TestUtil.BC_PROVIDER);
    bcKeyGen.initialize(TestUtil.getMlKemParamSpec(paramSet));
    KeyPair bcKeyPair = bcKeyGen.generateKeyPair();
    MLKEMPrivateKey bcPriv = (MLKEMPrivateKey) bcKeyPair.getPrivate();
    byte[] spki = bcKeyPair.getPublic().getEncoded();
    KeyFactory accpKf = KeyFactory.getInstance(paramSet, NATIVE_PROVIDER);

    PrivateKey fromSeed =
        accpKf.generatePrivate(new PKCS8EncodedKeySpec(bcPriv.getPrivateKey(true).getEncoded()));
    PublicKey pubFromSeed = TestUtil.sneakyInvoke(fromSeed, "getPublicKey");
    assertArrayEquals(
        spki,
        pubFromSeed.getEncoded(),
        paramSet + " a seed-derived private key must carry the matching public key");

    PrivateKey fromExpanded =
        accpKf.generatePrivate(new PKCS8EncodedKeySpec(bcPriv.getPrivateKey(false).getEncoded()));
    PublicKey pubFromExpanded = TestUtil.sneakyInvoke(fromExpanded, "getPublicKey");
    // An expandedKey-imported private key carries no public key, so encoding it fails.
    assertThrows(RuntimeCryptoException.class, pubFromExpanded::getEncoded);
  }

  @ParameterizedTest
  @MethodSource("mlKemParamSets")
  public void testPkcs8OneAsymmetricKeyFieldsAccepted(String paramSet) throws Exception {
    // A PKCS#8 ML-KEM private key may arrive as an RFC 5208 PrivateKeyInfo (version 0) or an
    // RFC 5958 OneAsymmetricKey (version 1, which also permits a [1] publicKey); both versions
    // permit an optional [0] attributes field. AWS-LC's EVP_parse_private_key accepts all of these,
    // and in regular FIPS builds ACCP's hand-rolled fallover parser is what has to accept them
    // instead, so exercise each shape. The assertion is encoding-independent: every variant carries
    // the same key material, so each must decapsulate to the same shared secret.
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance(paramSet, NATIVE_PROVIDER);
    KeyPair keyPair = keyGen.generateKeyPair();
    KeyFactory keyFactory = KeyFactory.getInstance(paramSet, NATIVE_PROVIDER);

    ASN1Sequence pkcs8 = ASN1Sequence.getInstance(keyPair.getPrivate().getEncoded());
    ASN1Encodable algorithm = pkcs8.getObjectAt(1);
    ASN1Encodable privateKey = pkcs8.getObjectAt(2);
    byte[] rawPublicKey =
        SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded())
            .getPublicKeyData()
            .getBytes();

    List<byte[]> variants = new ArrayList<>();
    // version 1 (OneAsymmetricKey) with no optional fields.
    variants.add(
        new DERSequence(new ASN1Encodable[] {new ASN1Integer(1), algorithm, privateKey})
            .getEncoded("DER"));
    // version 0 with an (empty) [0] attributes SET, which is encoded constructed.
    variants.add(
        new DERSequence(
                new ASN1Encodable[] {
                  new ASN1Integer(0),
                  algorithm,
                  privateKey,
                  new DERTaggedObject(false, 0, new DERSet())
                })
            .getEncoded("DER"));
    // version 1 with a [1] publicKey BIT STRING, which is encoded primitive.
    variants.add(
        new DERSequence(
                new ASN1Encodable[] {
                  new ASN1Integer(1),
                  algorithm,
                  privateKey,
                  new DERTaggedObject(false, 1, new DERBitString(rawPublicKey))
                })
            .getEncoded("DER"));

    KEM kem = KEM.getInstance(paramSet, NATIVE_PROVIDER);
    NamedParameterSpec paramSpec = new NamedParameterSpec(paramSet);
    KEM.Encapsulated encapsulated =
        kem.newEncapsulator(keyPair.getPublic(), paramSpec, null).encapsulate();
    byte[] ciphertext = encapsulated.encapsulation();

    for (byte[] variant : variants) {
      PrivateKey parsed = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(variant));
      assertArrayEquals(
          encapsulated.key().getEncoded(),
          kem.newDecapsulator(parsed, paramSpec).decapsulate(ciphertext).getEncoded(),
          paramSet + " OneAsymmetricKey variant must decapsulate to the same shared secret");
    }
  }

  @ParameterizedTest
  @MethodSource("mlKemParamSets")
  public void testMalformedPkcs8PrivateKeysRejected(String paramSet) throws Exception {
    // Negative counterpart to testPkcs8OneAsymmetricKeyFieldsAccepted. Every variant below is
    // outside the PKCS#8 grammar for ML-KEM, and each is rejected by both decoders that can see
    // it: AWS-LC's EVP_parse_private_key in non-FIPS and experimental-FIPS builds, and ACCP's
    // hand-rolled fallover parser in regular FIPS. There is exactly one input class the decoders
    // disagree on, both across builds and across AWS-LC versions; it is handled separately and
    // explained where it appears.
    ASN1Sequence pkcs8 =
        ASN1Sequence.getInstance(
            KeyPairGenerator.getInstance(paramSet, NATIVE_PROVIDER)
                .generateKeyPair()
                .getPrivate()
                .getEncoded());
    ASN1Encodable algorithm = pkcs8.getObjectAt(1);
    ASN1Encodable privateKey = pkcs8.getObjectAt(2);
    KeyFactory keyFactory = KeyFactory.getInstance(paramSet, NATIVE_PROVIDER);

    assertPrivateKeyRejected(
        keyFactory,
        paramSet + " unrecognized algorithm OID",
        new DERSequence(
                new ASN1Encodable[] {
                  new ASN1Integer(0),
                  new DERSequence(new ASN1ObjectIdentifier(UNASSIGNED_OID)),
                  privateKey
                })
            .getEncoded("DER"));

    // version 2 is outside both RFC 5208 (version 0) and RFC 5958 (version 1).
    assertPrivateKeyRejected(
        keyFactory,
        paramSet + " version 2",
        new DERSequence(new ASN1Encodable[] {new ASN1Integer(2), algorithm, privateKey})
            .getEncoded("DER"));

    // An expandedKey CHOICE whose length matches no ML-KEM parameter set. Written explicitly rather
    // than derived from the key above, because ACCP emits the seed CHOICE in non-FIPS builds.
    assertPrivateKeyRejected(
        keyFactory,
        paramSet + " expandedKey of invalid length",
        new DERSequence(
                new ASN1Encodable[] {
                  new ASN1Integer(0),
                  algorithm,
                  new DEROctetString(new DEROctetString(new byte[1631]).getEncoded("DER"))
                })
            .getEncoded("DER"));

    // Seed CHOICEs of the wrong size. Every ML-KEM parameter set uses a 64-byte keygen seed
    // (d || z), so each of these must be rejected outright rather than truncated, zero-padded, or
    // handed to EVP_PKEY_keygen_deterministic to validate. 0 exercises the empty OCTET STRING, 63
    // and 65 the off-by-one boundaries, and 128 a plausible-looking multiple of 64.
    for (int seedLen : new int[] {0, 63, 65, 128}) {
      assertPrivateKeyRejected(
          keyFactory,
          paramSet + " seed of " + seedLen + " bytes",
          pkcs8WithPrivateKeyChoice(
              algorithm, new DERTaggedObject(false, 0, new DEROctetString(new byte[seedLen]))));
    }

    // Wrong encoding form for each of the two optional trailing fields. ACCP's fallover parser
    // recognizes attributes only as a constructed [0] and publicKey only as a primitive [1], the
    // way AWS-LC v5.0.0 spells kAttributesTag and kPublicKeyTag, so it treats the other form of
    // either tag as unrecognized trailing data inside the SEQUENCE and rejects the key.
    //
    // A primitive [0] where attributes belong is rejected everywhere, though the pinned non-FIPS
    // AWS-LC v1.72.0 gets there by another route: its kAttributesTag is the primitive form, so it
    // matches, but it then tries to consume the field from the outer CBS it has already advanced
    // past the SEQUENCE, and fails.
    assertPrivateKeyRejected(
        keyFactory,
        paramSet + " primitive [0] attributes",
        new DERSequence(
                new ASN1Encodable[] {
                  new ASN1Integer(0),
                  algorithm,
                  privateKey,
                  new DERTaggedObject(false, 0, new DEROctetString(new byte[0]))
                })
            .getEncoded("DER"));

    // A constructed [1] where a primitive [1] publicKey belongs is the one input class the decoders
    // disagree on, and the disagreement is entirely on AWS-LC's side of it. ACCP's parser rejects
    // it, so regular FIPS -- where that parser is the whole ML-KEM decoder -- rejects it, and so
    // does AWS-LC v5.0.0 and later. The pinned v1.72.0 matches neither of its tags against 0xA1 and
    // never checks for trailing data inside the SEQUENCE, so it accepts the key and silently
    // ignores the field; in non-FIPS and experimental-FIPS builds d2i_PrivateKey therefore succeeds
    // before the fallover is consulted. ACCP is built against both the pinned tag and AWS-LC HEAD,
    // so pin neither answer: require only that the field is never absorbed into the key, which
    // leaves rejecting it and ignoring it equally acceptable.
    //
    // TODO [AWS-LC-FIPS 4.x]: collapse this to the tolerant branch alone once the FIPS module
    // implements priv_decode for ML-KEM. parseMLKEMPrivateKey goes away with it, and regular FIPS
    // then answers with AWS-LC-FIPS's decoder rather than ACCP's own.
    byte[] constructedPublicKey =
        new DERSequence(
                new ASN1Encodable[] {
                  new ASN1Integer(1),
                  algorithm,
                  privateKey,
                  new DERTaggedObject(true, 1, new DERBitString(new byte[32]))
                })
            .getEncoded("DER");
    if (NATIVE_PROVIDER.isFips() && !NATIVE_PROVIDER.isExperimentalFips()) {
      assertPrivateKeyRejected(
          keyFactory, paramSet + " constructed [1] publicKey", constructedPublicKey);
    } else {
      try {
        // If AWS-LC accepts the key, it must have ignored the field rather than absorbed any of it:
        // the result has to re-encode to exactly the key the bogus field was grafted onto.
        PrivateKey ignored =
            keyFactory.generatePrivate(new PKCS8EncodedKeySpec(constructedPublicKey));
        assertArrayEquals(
            pkcs8.getEncoded("DER"),
            ignored.getEncoded(),
            paramSet + " a constructed [1] publicKey must be ignored, not absorbed");
      } catch (InvalidKeySpecException expected) {
        // AWS-LC v5.0.0 and later reject it outright, which is the stricter of the two answers.
      }
    }

    // A publicKey field is permitted only in a version 1 OneAsymmetricKey.
    assertPrivateKeyRejected(
        keyFactory,
        paramSet + " version 0 with a publicKey",
        new DERSequence(
                new ASN1Encodable[] {
                  new ASN1Integer(0),
                  algorithm,
                  privateKey,
                  new DERTaggedObject(false, 1, new DERBitString(new byte[32]))
                })
            .getEncoded("DER"));

    // Trailing garbage after the PrivateKeyInfo SEQUENCE.
    byte[] valid =
        new DERSequence(new ASN1Encodable[] {new ASN1Integer(0), algorithm, privateKey})
            .getEncoded("DER");
    assertPrivateKeyRejected(
        keyFactory, paramSet + " trailing byte", Arrays.copyOf(valid, valid.length + 1));

    // Trailing garbage after the CHOICE but still inside the privateKey OCTET STRING. ACCP's parser
    // rejects this, which is deliberately stricter than kem_priv_decode: that function extracts the
    // CHOICE and never looks at what follows it, in every AWS-LC version. Ignoring the bytes would
    // let unbounded caller-controlled data ride along inside an encoding ACCP declares well-formed,
    // and would make two distinct DER encodings decode to the same key so that getEncoded() no
    // longer round-trips. Nothing any AWS-LC encoder emits has such trailing bytes, so the extra
    // strictness cannot refuse a key the library itself produced. As with the constructed [1]
    // publicKey above, only regular FIPS -- where ACCP's parser is the whole ML-KEM decoder -- can
    // be held to the stricter answer; elsewhere d2i_PrivateKey is consulted first and all that can
    // be required is that the trailing byte is not absorbed into the key.
    byte[] choice = ASN1OctetString.getInstance(privateKey).getOctets();
    byte[] trailingInsideChoice =
        new DERSequence(
                new ASN1Encodable[] {
                  new ASN1Integer(0),
                  algorithm,
                  new DEROctetString(Arrays.copyOf(choice, choice.length + 1))
                })
            .getEncoded("DER");
    if (NATIVE_PROVIDER.isFips() && !NATIVE_PROVIDER.isExperimentalFips()) {
      assertPrivateKeyRejected(
          keyFactory,
          paramSet + " trailing byte inside the privateKey OCTET STRING",
          trailingInsideChoice);
    } else {
      try {
        PrivateKey ignored =
            keyFactory.generatePrivate(new PKCS8EncodedKeySpec(trailingInsideChoice));
        assertArrayEquals(
            pkcs8.getEncoded("DER"),
            ignored.getEncoded(),
            paramSet + " a trailing byte inside the privateKey OCTET STRING must be ignored");
      } catch (InvalidKeySpecException expected) {
        // Rejecting it outright is the stricter of the two acceptable answers.
      }
    }
  }

  @ParameterizedTest
  @MethodSource("mlKemParamSets")
  public void testExpandPrivateKeyNormalizesEncoding(String paramSet) throws Exception {
    // MlKemUtils.expandPrivateKey parses and re-encodes every input rather than short-circuiting on
    // the input length the way its ML-DSA counterpart does, so its output is always the canonical
    // minimal expandedKey PKCS#8: version 0, no attributes, no publicKey. The optional
    // OneAsymmetricKey fields are accepted on input but are not carried over, so the method is
    // idempotent on its own output rather than byte-preserving on arbitrary input.
    KeyPair keyPair = KeyPairGenerator.getInstance(paramSet, NATIVE_PROVIDER).generateKeyPair();
    byte[] canonical = MlKemUtils.expandPrivateKey(keyPair.getPrivate());
    assertEquals(
        CHOICE_TAG_EXPANDED,
        privateKeyChoiceTag(canonical),
        paramSet + " expandPrivateKey must emit the expandedKey CHOICE");
    ASN1Sequence canonicalSeq = ASN1Sequence.getInstance(canonical);
    assertEquals(
        3, canonicalSeq.size(), paramSet + " expandPrivateKey must emit no optional fields");
    assertEquals(
        0,
        ASN1Integer.getInstance(canonicalSeq.getObjectAt(0)).intValueExact(),
        paramSet + " expandPrivateKey must emit a version 0 PrivateKeyInfo");
    assertArrayEquals(
        canonical,
        MlKemUtils.expandPrivateKey(rawPrivateKey(paramSet, canonical)),
        paramSet + " expandPrivateKey must be idempotent on its own output");

    // Decorate that canonical encoding with both optional fields a version 1 OneAsymmetricKey may
    // carry: a constructed [0] attributes SET and a primitive [1] publicKey BIT STRING. Both are
    // accepted, and both are dropped rather than reflected in the output.
    byte[] decorated =
        new DERSequence(
                new ASN1Encodable[] {
                  new ASN1Integer(1),
                  canonicalSeq.getObjectAt(1),
                  canonicalSeq.getObjectAt(2),
                  new DERTaggedObject(false, 0, new DERSet()),
                  new DERTaggedObject(false, 1, new DERBitString(new byte[32]))
                })
            .getEncoded("DER");
    assertArrayEquals(
        canonical,
        MlKemUtils.expandPrivateKey(rawPrivateKey(paramSet, decorated)),
        paramSet + " expandPrivateKey must drop attributes and publicKey");
  }

  @ParameterizedTest
  @MethodSource("mlKemParamSets")
  public void testMalformedSpkiPublicKeysRejected(String paramSet) throws Exception {
    // Every variant below is outside the X.509 SubjectPublicKeyInfo grammar for ML-KEM (RFC 9935
    // Section 4) and must be rejected both by AWS-LC's EVP_parse_public_key (the non-FIPS decoder)
    // and by ACCP's hand-rolled regular-FIPS fallover parser.
    KeyPair keyPair = KeyPairGenerator.getInstance(paramSet, NATIVE_PROVIDER).generateKeyPair();
    byte[] validSpki = keyPair.getPublic().getEncoded();
    ASN1Encodable algorithm = ASN1Sequence.getInstance(validSpki).getObjectAt(0);
    byte[] rawPublicKey = SubjectPublicKeyInfo.getInstance(validSpki).getPublicKeyData().getBytes();
    KeyFactory keyFactory = KeyFactory.getInstance(paramSet, NATIVE_PROVIDER);

    assertPublicKeyRejected(
        keyFactory,
        paramSet + " unrecognized algorithm OID",
        new DERSequence(
                new ASN1Encodable[] {
                  new DERSequence(new ASN1ObjectIdentifier(UNASSIGNED_OID)),
                  new DERBitString(rawPublicKey)
                })
            .getEncoded("DER"));

    // An ML-KEM public key is a whole number of octets, so the unused-bit count must be zero. Clear
    // the bit that padBits=1 declares unused so the BIT STRING itself stays well-formed DER.
    byte[] maskedPublicKey = rawPublicKey.clone();
    maskedPublicKey[maskedPublicKey.length - 1] &= (byte) 0xFE;
    assertPublicKeyRejected(
        keyFactory,
        paramSet + " non-zero unused bit count",
        new DERSequence(new ASN1Encodable[] {algorithm, new DERBitString(maskedPublicKey, 1)})
            .getEncoded("DER"));

    assertPublicKeyRejected(
        keyFactory,
        paramSet + " empty subjectPublicKey",
        new DERSequence(new ASN1Encodable[] {algorithm, new DERBitString(new byte[0])})
            .getEncoded("DER"));

    assertPublicKeyRejected(
        keyFactory,
        paramSet + " truncated subjectPublicKey",
        new DERSequence(
                new ASN1Encodable[] {
                  algorithm, new DERBitString(Arrays.copyOf(rawPublicKey, rawPublicKey.length - 1))
                })
            .getEncoded("DER"));

    assertPublicKeyRejected(
        keyFactory, paramSet + " trailing byte", Arrays.copyOf(validSpki, validSpki.length + 1));
  }

  @ParameterizedTest
  @MethodSource("mlKemParamSets")
  public void testPublicKeyEncodingMatchesBouncyCastle(String paramSet) throws Exception {
    // ML-KEM SPKI is fully determined by (OID, rawPublicKey), so unlike the private-key encoding it
    // has one canonical form in every build. That makes it a byte-for-byte check on ACCP's
    // hand-rolled regular-FIPS SPKI encoder, which is why this test carries no FIPS guard.
    KeyPair keyPair = KeyPairGenerator.getInstance(paramSet, NATIVE_PROVIDER).generateKeyPair();
    byte[] accpSpki = keyPair.getPublic().getEncoded();

    PublicKey bcPublicKey =
        KeyFactory.getInstance("ML-KEM", TestUtil.BC_PROVIDER)
            .generatePublic(new X509EncodedKeySpec(accpSpki));
    assertArrayEquals(
        accpSpki,
        bcPublicKey.getEncoded(),
        paramSet + " SPKI must round-trip byte-identically through BouncyCastle");

    PublicKey reparsed =
        KeyFactory.getInstance(paramSet, NATIVE_PROVIDER)
            .generatePublic(new X509EncodedKeySpec(accpSpki));
    assertArrayEquals(
        accpSpki, reparsed.getEncoded(), paramSet + " SPKI must round-trip unchanged through ACCP");
  }

  private static void assertPrivateKeyRejected(KeyFactory keyFactory, String label, byte[] der)
      throws Exception {
    try {
      keyFactory.generatePrivate(new PKCS8EncodedKeySpec(der));
      fail("Expected InvalidKeySpecException for " + label);
    } catch (InvalidKeySpecException expected) {
      // Expected: the encoding is outside the grammar ACCP accepts.
    }
  }

  // Contents of the privateKey OCTET STRING of a PKCS#8 ML-KEM private key, i.e. the DER of
  // whichever CHOICE of RFC 9935 Section 6 the encoding carries.
  private static byte[] privateKeyChoiceBytes(byte[] pkcs8) {
    return ASN1OctetString.getInstance(ASN1Sequence.getInstance(pkcs8).getObjectAt(2)).getOctets();
  }

  private static int privateKeyChoiceTag(byte[] pkcs8) {
    return privateKeyChoiceBytes(pkcs8)[0] & 0xFF;
  }

  // Wraps a private-key CHOICE, well-formed or not, in an otherwise valid version 0 PrivateKeyInfo.
  private static byte[] pkcs8WithPrivateKeyChoice(ASN1Encodable algorithm, ASN1Encodable choice)
      throws Exception {
    return new DERSequence(
            new ASN1Encodable[] {
              new ASN1Integer(0),
              algorithm,
              new DEROctetString(choice.toASN1Primitive().getEncoded("DER"))
            })
        .getEncoded("DER");
  }

  // MlKemUtils.expandPrivateKey takes a PrivateKey and forwards key.getEncoded(), so exercising it
  // on a hand-built encoding needs a key that hands those bytes back verbatim. Routing them through
  // a KeyFactory first would re-encode the key and discard the very fields under test.
  private static PrivateKey rawPrivateKey(String paramSet, byte[] der) {
    return new PrivateKey() {
      private static final long serialVersionUID = 1L;

      @Override
      public String getAlgorithm() {
        return paramSet;
      }

      @Override
      public String getFormat() {
        return "PKCS#8";
      }

      @Override
      public byte[] getEncoded() {
        return der.clone();
      }
    };
  }

  private static ASN1Encodable bothChoice(byte[] seed, byte[] expanded) {
    return new DERSequence(
        new ASN1Encodable[] {new DEROctetString(seed), new DEROctetString(expanded)});
  }

  private static void assertPublicKeyRejected(KeyFactory keyFactory, String label, byte[] der)
      throws Exception {
    try {
      keyFactory.generatePublic(new X509EncodedKeySpec(der));
      fail("Expected InvalidKeySpecException for " + label);
    } catch (InvalidKeySpecException expected) {
      // Expected: the encoding is outside the grammar ACCP accepts.
    }
  }

  @ParameterizedTest
  @MethodSource("mlKemParamSets")
  public void testCiphertextSizes(String paramSet) throws Throwable {
    int expectedSize = getCiphertextSizeForParamSet(paramSet);

    KeyPair pair = KeyPairGenerator.getInstance(paramSet, NATIVE_PROVIDER).generateKeyPair();
    KEM kem = KEM.getInstance(paramSet, NATIVE_PROVIDER);

    NamedParameterSpec paramSpec = new NamedParameterSpec(paramSet);
    KEM.Encapsulator encapsulator = kem.newEncapsulator(pair.getPublic(), paramSpec, null);
    KEM.Encapsulated encapsulated = encapsulator.encapsulate();

    assertEquals(
        expectedSize,
        encapsulated.encapsulation().length,
        "Ciphertext size should match expected value for " + paramSet);
  }

  @ParameterizedTest
  @MethodSource("mlKemParamSets")
  public void testEncapsulatorProperties(String paramSet) throws Throwable {
    int expectedCiphertextSize = getCiphertextSizeForParamSet(paramSet);

    KeyPair pair = KeyPairGenerator.getInstance(paramSet, NATIVE_PROVIDER).generateKeyPair();
    KEM kem = KEM.getInstance(paramSet, NATIVE_PROVIDER);
    NamedParameterSpec paramSpec = new NamedParameterSpec(paramSet);

    KEM.Encapsulator encapsulator = kem.newEncapsulator(pair.getPublic(), paramSpec, null);

    assertEquals(SHARED_SECRET_SIZE, encapsulator.secretSize(), "Secret size should be 32 bytes");
    assertEquals(
        expectedCiphertextSize,
        encapsulator.encapsulationSize(),
        "Ciphertext size should match expected value");
  }

  @ParameterizedTest
  @MethodSource("mlKemParamSets")
  public void testGenericAlgorithmHandling(String paramSet) throws Exception {
    KeyPair pair = KeyPairGenerator.getInstance(paramSet, NATIVE_PROVIDER).generateKeyPair();
    KEM kem = KEM.getInstance(paramSet, NATIVE_PROVIDER);
    NamedParameterSpec paramSpec = new NamedParameterSpec(paramSet);

    KEM.Encapsulator encapsulator = kem.newEncapsulator(pair.getPublic(), paramSpec, null);
    KEM.Decapsulator decapsulator = kem.newDecapsulator(pair.getPrivate(), paramSpec);

    KEM.Encapsulated encapsulatedGeneric =
        encapsulator.encapsulate(0, SHARED_SECRET_SIZE, "Generic");

    assertNotNull(encapsulatedGeneric, "Encapsulated result should not be null");
    assertNotNull(encapsulatedGeneric.key(), "Shared secret should not be null");
    assertEquals(
        SHARED_SECRET_SIZE,
        encapsulatedGeneric.key().getEncoded().length,
        "Shared secret should be 32 bytes");

    // "Generic" should be preserved as-is
    assertEquals(
        "Generic",
        encapsulatedGeneric.key().getAlgorithm(),
        "Generic algorithm should be preserved");

    SecretKey recoveredGeneric =
        decapsulator.decapsulate(
            encapsulatedGeneric.encapsulation(), 0, SHARED_SECRET_SIZE, "Generic");

    assertNotNull(recoveredGeneric, "Recovered secret should not be null");
    assertEquals(
        SHARED_SECRET_SIZE,
        recoveredGeneric.getEncoded().length,
        "Recovered secret should be 32 bytes");
    assertEquals(
        "Generic", recoveredGeneric.getAlgorithm(), "Generic algorithm should be preserved");

    assertArrayEquals(
        encapsulatedGeneric.key().getEncoded(),
        recoveredGeneric.getEncoded(),
        "Encapsulated and decapsulated secrets should match");

    KEM.Encapsulated encapsulatedSpecific =
        encapsulator.encapsulate(0, SHARED_SECRET_SIZE, paramSet);
    assertEquals(
        paramSet,
        encapsulatedSpecific.key().getAlgorithm(),
        "Specific algorithm should be preserved");

    // Test that ML-KEM generic also works
    KEM.Encapsulated encapsulatedMlKem = encapsulator.encapsulate(0, SHARED_SECRET_SIZE, "ML-KEM");
    assertEquals(
        "ML-KEM", encapsulatedMlKem.key().getAlgorithm(), "ML-KEM algorithm should be preserved");
  }

  @ParameterizedTest
  @MethodSource("mlKemParamSets")
  public void testPrivateKeyEncodingIsSeedFormat(String paramSet) throws Exception {
    // ACCP cannot EMIT the seed encoding in regular FIPS: AWS-LC-FIPS 3.1.0 stores no keygen
    // seed, so getEncoded() produces the expanded form instead. (Seed PARSING is supported
    // everywhere; see testPrivateKeyChoicesParse, which also pins the expanded form regular FIPS
    // emits here.)
    // TODO [AWS-LC-FIPS 5.0]: drop this guard once the module retains the seed and can re-emit it.
    assumeTrue(
        !NATIVE_PROVIDER.isFips() || NATIVE_PROVIDER.isExperimentalFips(),
        "ML-KEM seed-format encoding is unavailable in regular FIPS");
    // Seed format is 64 bytes (d || z) for all ML-KEM parameter sets.
    // PKCS#8 DER wrapping adds 22 bytes of ASN.1 overhead, totaling 86 bytes.
    // Expanded format would be 1632/2400/3168 bytes plus overhead.
    final int expectedSeedEncodingLength = 86;

    KeyPair kp = KeyPairGenerator.getInstance(paramSet, NATIVE_PROVIDER).generateKeyPair();
    byte[] encoded = kp.getPrivate().getEncoded();

    assertEquals(
        expectedSeedEncodingLength,
        encoded.length,
        paramSet + " private key should be 86 bytes (64-byte seed + PKCS#8 overhead)");
  }

  @ParameterizedTest
  @MethodSource("mlKemParamSets")
  public void testBouncyCastleInteroperability(String paramSet) throws Exception {
    KeyPair accpKeyPair = KeyPairGenerator.getInstance(paramSet, NATIVE_PROVIDER).generateKeyPair();

    // Test BouncyCastle can import ACCP keys
    KeyFactory bcKf = KeyFactory.getInstance("ML-KEM", TestUtil.BC_PROVIDER);
    PublicKey bcPub =
        bcKf.generatePublic(new X509EncodedKeySpec(accpKeyPair.getPublic().getEncoded()));
    PrivateKey bcPriv =
        bcKf.generatePrivate(new PKCS8EncodedKeySpec(accpKeyPair.getPrivate().getEncoded()));

    assertNotNull(bcPub, "BouncyCastle should import ACCP public key");
    assertNotNull(bcPriv, "BouncyCastle should import ACCP private key");
    assertArrayEquals(
        accpKeyPair.getPublic().getEncoded(),
        bcPub.getEncoded(),
        "Public key encoding should be preserved");
    assertArrayEquals(
        accpKeyPair.getPrivate().getEncoded(),
        bcPriv.getEncoded(),
        "Private key encoding should be preserved");

    // The expanded encoding is ACCP's other private-key output, and MlKemUtils.expandPrivateKey is
    // the only way to obtain it in builds whose getEncoded() emits the seed. Feeding it to BC too
    // means every private-key encoding ACCP can produce is checked against BC in this test.
    byte[] accpExpanded = MlKemUtils.expandPrivateKey(accpKeyPair.getPrivate());
    PrivateKey bcPrivFromExpanded = bcKf.generatePrivate(new PKCS8EncodedKeySpec(accpExpanded));
    assertArrayEquals(
        accpExpanded,
        bcPrivFromExpanded.getEncoded(),
        "Expanded private key encoding should be preserved");
    assertArrayEquals(
        ((MLKEMPrivateKey) bcPriv).getPrivateKey(false).getEncoded(),
        accpExpanded,
        "BouncyCastle and ACCP should agree on the expanded encoding of the same key");

    // Test BC keys and convert to ACCP using ACCP's key factory, test if they're equal
    KeyPairGenerator bcKeyGen = KeyPairGenerator.getInstance("ML-KEM", TestUtil.BC_PROVIDER);
    bcKeyGen.initialize(TestUtil.getMlKemParamSpec(paramSet));
    KeyPair bcKeyPair = bcKeyGen.generateKeyPair();

    // Ask BC for the expandedKey CHOICE specifically, per RFC 9935 Section 6, so this stays a
    // like-for-like comparison of re-encodings: an expandedKey-imported ACCP key has no seed to
    // emit, so it round-trips to the expanded form in every build. testPrivateKeyChoicesParse
    // covers the seed CHOICE.
    // https://github.com/bcgit/bc-java/blob/b41f23936724284a20f10dff13c76896a846031b/prov/src/main/java/org/bouncycastle/jcajce/interfaces/MLKEMPrivateKey.java#L35
    MLKEMPrivateKey bcPrivateKeyExpanded =
        ((MLKEMPrivateKey) bcKeyPair.getPrivate()).getPrivateKey(false);

    KeyFactory accpKeyFactory =
        KeyFactory.getInstance(bcKeyPair.getPrivate().getAlgorithm(), NATIVE_PROVIDER);
    PublicKey accpPublicKey =
        accpKeyFactory.generatePublic(new X509EncodedKeySpec(bcKeyPair.getPublic().getEncoded()));
    PrivateKey accpPrivateKey =
        accpKeyFactory.generatePrivate(new PKCS8EncodedKeySpec(bcPrivateKeyExpanded.getEncoded()));
    assertArrayEquals(accpPublicKey.getEncoded(), bcKeyPair.getPublic().getEncoded());
    assertArrayEquals(accpPrivateKey.getEncoded(), bcPrivateKeyExpanded.getEncoded());

    // Test ACCP's encapsulation can be decapsulated by BouncyCastle
    KEM accpKem = KEM.getInstance(paramSet, NATIVE_PROVIDER);
    NamedParameterSpec accpParamSpec = new NamedParameterSpec(paramSet);
    KEM.Encapsulated encapsulated =
        accpKem.newEncapsulator(accpKeyPair.getPublic(), accpParamSpec, null).encapsulate();

    // BouncyCastle does not register the KEM API for ML-KEM on JDK versions older than JDK 21
    // We need to check the runtime environment supports BouncyCastle's KEM API
    boolean bcHasKemProvider = false;
    try {
      KEM.getInstance("ML-KEM", TestUtil.BC_PROVIDER);
      bcHasKemProvider = true;
    } catch (java.security.NoSuchAlgorithmException e) {

      bcHasKemProvider = false;
    }
    // Skip the test if BouncyCastle doesn't support KEM API
    assumeTrue(
        bcHasKemProvider,
        "BouncyCastle does not register the KEM API on JDK versions older than 21. Please try"
            + " building with JDK 21 or above.");

    KEM bcKem = KEM.getInstance("ML-KEM", TestUtil.BC_PROVIDER); // BC uses Generic ML-KEM

    // Configure BC to not apply KDF processing to get raw shared secret
    KTSParameterSpec bcParamSpec = new KTSParameterSpec.Builder("Generic", 256).withNoKdf().build();
    SecretKey bcSecret =
        bcKem.newDecapsulator(bcPriv, bcParamSpec).decapsulate(encapsulated.encapsulation());
    assertArrayEquals(
        encapsulated.key().getEncoded(),
        bcSecret.getEncoded(),
        "ACCP and BouncyCastle should produce identical shared secrets for " + paramSet);
  }

  @ParameterizedTest
  @MethodSource("mlKemParamSets")
  public void testDecapsulationEquivalenceSeedAndExpanded(String paramSet) throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance(paramSet, NATIVE_PROVIDER);
    KeyPair keyPair = keyGen.generateKeyPair();

    // Encapsulate against the public key
    KEM kem = KEM.getInstance(paramSet, NATIVE_PROVIDER);
    NamedParameterSpec paramSpec = new NamedParameterSpec(paramSet);
    KEM.Encapsulated encapsulated =
        kem.newEncapsulator(keyPair.getPublic(), paramSpec, null).encapsulate();
    byte[] ciphertext = encapsulated.encapsulation();

    // Decapsulate with the original (seed-format) private key
    SecretKey secretFromSeed =
        kem.newDecapsulator(keyPair.getPrivate(), paramSpec).decapsulate(ciphertext);

    // Expand the private key and decapsulate with the expanded form
    byte[] expandedDer = MlKemUtils.expandPrivateKey(keyPair.getPrivate());
    KeyFactory kf = KeyFactory.getInstance("ML-KEM", NATIVE_PROVIDER);
    PrivateKey expandedKey = kf.generatePrivate(new PKCS8EncodedKeySpec(expandedDer));
    SecretKey secretFromExpanded =
        kem.newDecapsulator(expandedKey, paramSpec).decapsulate(ciphertext);

    assertArrayEquals(
        secretFromSeed.getEncoded(),
        secretFromExpanded.getEncoded(),
        "Seed and expanded keys must produce identical shared secrets for " + paramSet);
  }
}
