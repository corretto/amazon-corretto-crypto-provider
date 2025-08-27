// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import com.amazon.corretto.crypto.provider.EvpKemPrivateKey;
import com.amazon.corretto.crypto.provider.EvpKemPublicKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.NamedParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
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

    SecretKey originalSecret = encapsulated.key();
    byte[] ciphertext = encapsulated.encapsulation();

    assertEquals(32, originalSecret.getEncoded().length, "Shared secret should be 32 bytes");

    KEM.Decapsulator decapsulator = decapsulatorKem.newDecapsulator(params.priv, paramSpec);
    SecretKey recoveredSecret = decapsulator.decapsulate(ciphertext);

    assertNotNull(recoveredSecret, "Recovered secret should not be null");
    assertEquals(32, recoveredSecret.getEncoded().length, "Recovered secret should be 32 bytes");

    assertArrayEquals(
        originalSecret.getEncoded(),
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

    assertTrue(
        keyPair.getPrivate() instanceof EvpKemPrivateKey, "Private key should be EvpKemPrivateKey");
    assertTrue(
        keyPair.getPublic() instanceof EvpKemPublicKey, "Public key should be EvpKemPublicKey");
  }

  @Test
  public void testParameterSetValidation() throws Exception {
    KeyPair pair512 = KeyPairGenerator.getInstance("ML-KEM-512", NATIVE_PROVIDER).generateKeyPair();
    KeyPair pair768 = KeyPairGenerator.getInstance("ML-KEM-768", NATIVE_PROVIDER).generateKeyPair();
    KeyPair pair1024 =
        KeyPairGenerator.getInstance("ML-KEM-1024", NATIVE_PROVIDER).generateKeyPair();

    EvpKemPublicKey pub512 = (EvpKemPublicKey) pair512.getPublic();
    EvpKemPublicKey pub768 = (EvpKemPublicKey) pair768.getPublic();
    EvpKemPublicKey pub1024 = (EvpKemPublicKey) pair1024.getPublic();

    assertEquals(512, pub512.getParameterSet().getParameterSize());
    assertEquals(768, pub768.getParameterSet().getParameterSize());
    assertEquals(1024, pub1024.getParameterSet().getParameterSize());

    assertEquals("ML-KEM-512", pub512.getAlgorithm());
    assertEquals("ML-KEM-768", pub768.getAlgorithm());
    assertEquals("ML-KEM-1024", pub1024.getAlgorithm());
  }

  @Test
  public void testParameterSpecMismatch() throws Exception {
    KeyPair pair768 = KeyPairGenerator.getInstance("ML-KEM-768", NATIVE_PROVIDER).generateKeyPair();
    KEM kem512 = KEM.getInstance("ML-KEM-512", NATIVE_PROVIDER);

    NamedParameterSpec wrongSpec = new NamedParameterSpec("ML-KEM-512"); // Wrong for 768 key

    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> kem512.newEncapsulator(pair768.getPublic(), wrongSpec, null));
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> kem512.newDecapsulator(pair768.getPrivate(), wrongSpec));
  }

  @Test
  public void testNullParameterSpec() throws Exception {
    KeyPair pair512 = KeyPairGenerator.getInstance("ML-KEM-512", NATIVE_PROVIDER).generateKeyPair();
    KEM kem = KEM.getInstance("ML-KEM-512", NATIVE_PROVIDER);

    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> kem.newEncapsulator(pair512.getPublic(), null, null));

    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> kem.newDecapsulator(pair512.getPrivate(), null));
  }

  @Test
  public void testInvalidKeyInitialization() {
    assertThrows(
        InvalidKeyException.class,
        () -> {
          KeyPair rsaKeys = KeyPairGenerator.getInstance("RSA").generateKeyPair();
          KEM kem = KEM.getInstance("ML-KEM-512", NATIVE_PROVIDER);
          kem.newEncapsulator(rsaKeys.getPublic());
        });
  }

  @Test
  public void testErrorHandling() throws Exception {
    KeyPair pair = KeyPairGenerator.getInstance("ML-KEM-512", NATIVE_PROVIDER).generateKeyPair();
    KEM kem = KEM.getInstance("ML-KEM-512", NATIVE_PROVIDER);
    NamedParameterSpec paramSpec = new NamedParameterSpec("ML-KEM-512");

    assertThrows(
        InvalidKeyException.class,
        () -> {
          kem.newEncapsulator(null, paramSpec, null);
        });

    assertThrows(
        InvalidKeyException.class,
        () -> {
          kem.newDecapsulator(null, paramSpec);
        });

    KEM.Decapsulator decapsulator = kem.newDecapsulator(pair.getPrivate(), paramSpec);
    byte[] invalidCiphertext = new byte[10];

    assertThrows(
        Exception.class,
        () -> {
          decapsulator.decapsulate(invalidCiphertext);
        });
  }

  @Test
  public void testCiphertextSizes() throws Exception {
    String[] paramSets = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"};
    int[] expectedSizes = {768, 1088, 1568};

    for (int i = 0; i < paramSets.length; i++) {
      KeyPair pair = KeyPairGenerator.getInstance(paramSets[i], NATIVE_PROVIDER).generateKeyPair();
      KEM kem = KEM.getInstance(paramSets[i], NATIVE_PROVIDER);

      NamedParameterSpec paramSpec = new NamedParameterSpec(paramSets[i]);
      KEM.Encapsulator encapsulator = kem.newEncapsulator(pair.getPublic(), paramSpec, null);
      KEM.Encapsulated encapsulated = encapsulator.encapsulate();

      assertEquals(
          expectedSizes[i],
          encapsulated.encapsulation().length,
          "Ciphertext size should match expected value for " + paramSets[i]);
    }
  }

  @Test
  public void testEncapsulatorProperties() throws Exception {
    String[] paramSets = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"};
    int[] expectedCiphertextSizes = {768, 1088, 1568};

    for (int i = 0; i < paramSets.length; i++) {
      KeyPair pair = KeyPairGenerator.getInstance(paramSets[i], NATIVE_PROVIDER).generateKeyPair();
      KEM kem = KEM.getInstance(paramSets[i], NATIVE_PROVIDER);
      NamedParameterSpec paramSpec = new NamedParameterSpec(paramSets[i]);

      KEM.Encapsulator encapsulator = kem.newEncapsulator(pair.getPublic(), paramSpec, null);

      assertEquals(32, encapsulator.secretSize(), "Secret size should be 32 bytes");
      assertEquals(
          expectedCiphertextSizes[i],
          encapsulator.encapsulationSize(),
          "Ciphertext size should match expected value");
    }
  }

  @Test
  public void testSharedSecretConsistency() throws Exception {
    for (String paramSet : new String[] {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}) {
      KeyPair pair = KeyPairGenerator.getInstance(paramSet, NATIVE_PROVIDER).generateKeyPair();
      KEM kem = KEM.getInstance(paramSet, NATIVE_PROVIDER);
      NamedParameterSpec paramSpec = new NamedParameterSpec(paramSet);

      KEM.Encapsulator encapsulator = kem.newEncapsulator(pair.getPublic(), paramSpec, null);
      KEM.Decapsulator decapsulator = kem.newDecapsulator(pair.getPrivate(), paramSpec);

      KEM.Encapsulated enc1 = encapsulator.encapsulate();
      KEM.Encapsulated enc2 = encapsulator.encapsulate();

      assertNotEquals(
          Arrays.toString(enc1.encapsulation()),
          Arrays.toString(enc2.encapsulation()),
          "Ciphertexts should be different due to randomization");

      SecretKey secret1 = decapsulator.decapsulate(enc1.encapsulation());
      SecretKey secret2 = decapsulator.decapsulate(enc2.encapsulation());

      assertEquals(32, secret1.getEncoded().length);
      assertEquals(32, secret2.getEncoded().length);
      assertArrayEquals(enc1.key().getEncoded(), secret1.getEncoded());
      assertArrayEquals(enc2.key().getEncoded(), secret2.getEncoded());
    }
  }

  @Test
  public void testGenericAlgorithmHandling() throws Exception {
    String[] paramSets = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"};

    for (String paramSet : paramSets) {
      KeyPair pair = KeyPairGenerator.getInstance(paramSet, NATIVE_PROVIDER).generateKeyPair();
      KEM kem = KEM.getInstance(paramSet, NATIVE_PROVIDER);
      NamedParameterSpec paramSpec = new NamedParameterSpec(paramSet);

      KEM.Encapsulator encapsulator = kem.newEncapsulator(pair.getPublic(), paramSpec, null);
      KEM.Decapsulator decapsulator = kem.newDecapsulator(pair.getPrivate(), paramSpec);

      // Test encapsulation with "Generic" algorithm
      KEM.Encapsulated encapsulatedGeneric = encapsulator.encapsulate(0, 32, "Generic");

      assertNotNull(encapsulatedGeneric, "Encapsulated result should not be null");
      assertNotNull(encapsulatedGeneric.key(), "Shared secret should not be null");
      assertEquals(
          32, encapsulatedGeneric.key().getEncoded().length, "Shared secret should be 32 bytes");

      // "Generic" should be converted to specific algorithm name
      assertEquals(
          paramSet,
          encapsulatedGeneric.key().getAlgorithm(),
          "Generic algorithm should be converted to " + paramSet);

      // Test decapsulation with "Generic" algorithm
      SecretKey recoveredGeneric =
          decapsulator.decapsulate(encapsulatedGeneric.encapsulation(), 0, 32, "Generic");

      assertNotNull(recoveredGeneric, "Recovered secret should not be null");
      assertEquals(32, recoveredGeneric.getEncoded().length, "Recovered secret should be 32 bytes");
      assertEquals(
          paramSet,
          recoveredGeneric.getAlgorithm(),
          "Generic algorithm should be converted to " + paramSet);

      // Verify secrets match
      assertArrayEquals(
          encapsulatedGeneric.key().getEncoded(),
          recoveredGeneric.getEncoded(),
          "Encapsulated and decapsulated secrets should match");

      // Test that specific algorithm name also works
      KEM.Encapsulated encapsulatedSpecific = encapsulator.encapsulate(0, 32, paramSet);
      assertEquals(
          paramSet,
          encapsulatedSpecific.key().getAlgorithm(),
          "Specific algorithm should be preserved");

      // Test that ML-KEM generic also works
      KEM.Encapsulated encapsulatedMlKem = encapsulator.encapsulate(0, 32, "ML-KEM");
      assertEquals(
          "ML-KEM", encapsulatedMlKem.key().getAlgorithm(), "ML-KEM algorithm should be preserved");
    }
  }
}
