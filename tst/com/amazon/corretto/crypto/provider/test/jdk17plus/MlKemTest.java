// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
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
import org.junit.jupiter.params.provider.ValueSource;

@Execution(ExecutionMode.CONCURRENT)
@ExtendWith(TestResultLogger.class)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class MlKemTest {
  private static final AmazonCorrettoCryptoProvider NATIVE_PROVIDER =
      AmazonCorrettoCryptoProvider.INSTANCE;
  private static final int SHARED_SECRET_SIZE = 32;

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
    for (String paramSet : new String[] {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}) {
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
  @ValueSource(strings = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
  public void testKeyGeneration(String paramSet) throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance(paramSet, NATIVE_PROVIDER);
    KeyPair keyPair = keyGen.generateKeyPair();

    assertNotNull(keyPair);
    assertNotNull(keyPair.getPrivate());
    assertNotNull(keyPair.getPublic());

    assertEquals(paramSet, keyPair.getPrivate().getAlgorithm());
    assertEquals(paramSet, keyPair.getPublic().getAlgorithm());
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
  @ValueSource(strings = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
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
  @ValueSource(strings = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
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
  @ValueSource(strings = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
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
  @ValueSource(strings = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
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
}
