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
    // generateKeyPair
    // works with no initialize() call at all -- the path a caller that never sets a spec takes.
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
    // Round-trips ACCP's own ML-KEM key pair through its KeyFactory. In regular FIPS the private
    // key
    // serializes in expanded format (seed format is unavailable there), so this exercises the
    // expanded encode/decode; in other builds it exercises the seed format. Public keys use X.509.
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
  public void testSeedFormatPrivateKeyParses(String paramSet) throws Exception {
    // ACCP cannot *emit* seed-format ML-KEM private keys in regular FIPS (AWS-LC-FIPS 3.1.0 stores
    // no
    // keygen seed, so getEncoded emits the expanded form), but it can *parse* one: a seed-format
    // PKCS#8 is expanded into a full key via EVP_PKEY_keygen_deterministic. This verifies that path
    // by importing a BouncyCastle-produced key in both its seed and expanded encodings and
    // confirming
    // the two ACCP keys decapsulate a ciphertext to the same shared secret. The assertion is
    // encoding-independent, so it runs in all builds (regular FIPS uses the hand-rolled seed
    // expansion; other builds parse the seed via AWS-LC directly).
    KeyPairGenerator bcKeyGen = KeyPairGenerator.getInstance("ML-KEM", TestUtil.BC_PROVIDER);
    bcKeyGen.initialize(TestUtil.getMlKemParamSpec(paramSet));
    KeyPair bcKeyPair = bcKeyGen.generateKeyPair();
    MLKEMPrivateKey bcPriv = (MLKEMPrivateKey) bcKeyPair.getPrivate();

    KeyFactory accpKf = KeyFactory.getInstance(paramSet, NATIVE_PROVIDER);
    // getPrivateKey(true) yields the seed-format encoding; getPrivateKey(false) the expanded form.
    PrivateKey fromSeed =
        accpKf.generatePrivate(new PKCS8EncodedKeySpec(bcPriv.getPrivateKey(true).getEncoded()));
    PrivateKey fromExpanded =
        accpKf.generatePrivate(new PKCS8EncodedKeySpec(bcPriv.getPrivateKey(false).getEncoded()));
    PublicKey accpPub =
        accpKf.generatePublic(new X509EncodedKeySpec(bcKeyPair.getPublic().getEncoded()));

    KEM kem = KEM.getInstance(paramSet, NATIVE_PROVIDER);
    NamedParameterSpec paramSpec = new NamedParameterSpec(paramSet);
    KEM.Encapsulated encapsulated = kem.newEncapsulator(accpPub, paramSpec, null).encapsulate();
    byte[] ciphertext = encapsulated.encapsulation();

    SecretKey secretFromSeed = kem.newDecapsulator(fromSeed, paramSpec).decapsulate(ciphertext);
    SecretKey secretFromExpanded =
        kem.newDecapsulator(fromExpanded, paramSpec).decapsulate(ciphertext);

    assertArrayEquals(
        encapsulated.key().getEncoded(),
        secretFromSeed.getEncoded(),
        paramSet + " seed-parsed private key must decapsulate to the encapsulated shared secret");
    assertArrayEquals(
        secretFromExpanded.getEncoded(),
        secretFromSeed.getEncoded(),
        paramSet + " seed-parsed and expanded-parsed keys must decapsulate identically");
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
    // outside
    // the PKCS#8 grammar for ML-KEM and must be rejected both by AWS-LC's EVP_parse_private_key
    // (the
    // non-FIPS decoder) and by ACCP's hand-rolled regular-FIPS fallover parser.
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

    // Trailing garbage after the PrivateKeyInfo SEQUENCE.
    byte[] valid =
        new DERSequence(new ASN1Encodable[] {new ASN1Integer(0), algorithm, privateKey})
            .getEncoded("DER");
    assertPrivateKeyRejected(
        keyFactory, paramSet + " trailing byte", Arrays.copyOf(valid, valid.length + 1));
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
    // ACCP cannot EMIT the seed encoding in regular FIPS: AWS-LC-FIPS 3.1.0 stores no keygen seed,
    // so
    // getEncoded() produces the expanded form instead. (Seed PARSING is supported -- see
    // testSeedFormatPrivateKeyParses.) TODO: remove this guard once AWS-LC-FIPS is bumped to
    // v5.0.0,
    // which retains the seed and can re-emit it.
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
    // This interop compares seed-format private-key encodings across providers, which needs ACCP to
    // EMIT seed format; ACCP emits the expanded form in regular FIPS (AWS-LC-FIPS 3.1.0 stores no
    // seed). Seed PARSING is supported -- see testSeedFormatPrivateKeyParses for a FIPS-capable BC
    // seed round-trip. TODO: remove this guard once AWS-LC-FIPS is bumped to v5.0.0.
    assumeTrue(
        !NATIVE_PROVIDER.isFips() || NATIVE_PROVIDER.isExperimentalFips(),
        "ML-KEM seed-format encoding is unavailable in regular FIPS");

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

    // Test BC keys and convert to ACCP using ACCP's key factory, test if they're equal
    KeyPairGenerator bcKeyGen = KeyPairGenerator.getInstance("ML-KEM", TestUtil.BC_PROVIDER);
    bcKeyGen.initialize(TestUtil.getMlKemParamSpec(paramSet));
    KeyPair bcKeyPair = bcKeyGen.generateKeyPair();

    // set BC's private key to be encoded in expandedKey format, not seed, by passing false to
    // getPrivateKey(), per https://datatracker.ietf.org/doc/draft-ietf-lamps-kyber-certificates/
    // This is due to AWS-LC currently only supporting expandedKey format for encode/decode
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
    // This test expands via MlKemUtils.expandPrivateKey, whose native method
    // (expandPrivateKeyInternal) is compiled only in non-FIPS / experimental-FIPS builds. Seed
    // PARSING itself is supported in regular FIPS -- see testSeedFormatPrivateKeyParses.
    assumeTrue(
        !NATIVE_PROVIDER.isFips() || NATIVE_PROVIDER.isExperimentalFips(),
        "MlKemUtils.expandPrivateKey is unavailable in regular FIPS");
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
