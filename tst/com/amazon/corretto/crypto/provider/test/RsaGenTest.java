// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static com.amazon.corretto.crypto.provider.test.TestUtil.assumeMinimumVersion;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import com.amazon.corretto.crypto.provider.RuntimeCryptoException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.Cipher;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class RsaGenTest {
  private static final byte[] PLAINTEXT = new byte[32];

  private KeyPairGenerator getGenerator() throws GeneralSecurityException {
    return KeyPairGenerator.getInstance("RSA", TestUtil.NATIVE_PROVIDER);
  }

  @Test
  public void noInit() throws GeneralSecurityException {
    final KeyPairGenerator generator = getGenerator();
    final KeyPair keyPair = generator.generateKeyPair();
    final RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();
    final RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();

    assertConsistency(pubKey, privKey);
  }

  @Test
  public void test128() throws GeneralSecurityException {
    assumeMinimumVersion("1.1.0", AmazonCorrettoCryptoProvider.INSTANCE);
    final KeyPairGenerator generator = getGenerator();
    assertThrows(InvalidParameterException.class, () -> generator.initialize(128));
  }

  @Test
  public void test512() throws GeneralSecurityException {
    final KeyPairGenerator generator = getGenerator();
    if (TestUtil.isFips()) {
      assertThrows(InvalidParameterException.class, () -> generator.initialize(512));
    } else {
      generator.initialize(512);
      final KeyPair keyPair = generator.generateKeyPair();
      final RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();
      final RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();
      assertEquals(512, pubKey.getModulus().bitLength());
      assertEquals(RSAKeyGenParameterSpec.F4, pubKey.getPublicExponent());
      assertConsistency(pubKey, privKey);
    }
  }

  @Test
  public void test512_3() throws GeneralSecurityException {
    final KeyPairGenerator generator = getGenerator();
    if (TestUtil.isFips()) {
      assertThrows(
          InvalidAlgorithmParameterException.class,
          () -> generator.initialize(new RSAKeyGenParameterSpec(512, RSAKeyGenParameterSpec.F0)));
    } else {
      generator.initialize(new RSAKeyGenParameterSpec(512, RSAKeyGenParameterSpec.F0));
      final KeyPair keyPair = generator.generateKeyPair();
      final RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();
      final RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();
      assertEquals(512, pubKey.getModulus().bitLength());
      assertEquals(RSAKeyGenParameterSpec.F0, pubKey.getPublicExponent());
      assertConsistency(pubKey, privKey);
    }
  }

  @Test
  public void test1024() throws GeneralSecurityException {
    final KeyPairGenerator generator = getGenerator();
    if (TestUtil.isFips()) {
      assertThrows(InvalidParameterException.class, () -> generator.initialize(1024));
    } else {
      generator.initialize(1024);
      final KeyPair keyPair = generator.generateKeyPair();
      final RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();
      final RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();
      assertEquals(1024, pubKey.getModulus().bitLength());
      assertEquals(RSAKeyGenParameterSpec.F4, pubKey.getPublicExponent());
      assertConsistency(pubKey, privKey);
    }
  }

  @Test
  public void test2048() throws GeneralSecurityException {
    final KeyPairGenerator generator = getGenerator();
    generator.initialize(2048);
    final KeyPair keyPair = generator.generateKeyPair();
    final RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();
    final RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();
    assertEquals(2048, pubKey.getModulus().bitLength());
    assertEquals(RSAKeyGenParameterSpec.F4, pubKey.getPublicExponent());
    assertConsistency(pubKey, privKey);
  }

  @Test
  public void test3072() throws GeneralSecurityException {
    final KeyPairGenerator generator = getGenerator();
    generator.initialize(3072);
    final KeyPair keyPair = generator.generateKeyPair();
    final RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();
    final RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();
    assertEquals(3072, pubKey.getModulus().bitLength());
    assertEquals(RSAKeyGenParameterSpec.F4, pubKey.getPublicExponent());
    assertConsistency(pubKey, privKey);
  }

  // We want to ensure that when we ask for a strange keylength we get something of at least that
  // strength.
  @Test
  public void test3073() throws GeneralSecurityException {
    assumeFalse(
        AmazonCorrettoCryptoProvider.INSTANCE.isFips(),
        "Keysize of 3073 is not supported with FIPS");
    final KeyPairGenerator generator = getGenerator();
    generator.initialize(3073);
    final KeyPair keyPair = generator.generateKeyPair();
    final RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();
    final RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();
    assertTrue(3073 <= pubKey.getModulus().bitLength());
    assertEquals(RSAKeyGenParameterSpec.F4, pubKey.getPublicExponent());
    assertConsistency(pubKey, privKey);
  }

  @Test
  public void test4096() throws GeneralSecurityException {
    final KeyPairGenerator generator = getGenerator();
    generator.initialize(4096);
    final KeyPair keyPair = generator.generateKeyPair();
    final RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();
    final RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();
    assertEquals(4096, pubKey.getModulus().bitLength());
    assertEquals(RSAKeyGenParameterSpec.F4, pubKey.getPublicExponent());
    assertConsistency(pubKey, privKey);
  }

  @Test
  public void test5120() throws GeneralSecurityException {
    final KeyPairGenerator generator = getGenerator();
    generator.initialize(5120);
    try {
      final KeyPair keyPair = generator.generateKeyPair();
      final RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();
      final RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();
      assertEquals(5120, pubKey.getModulus().bitLength());
      assertEquals(RSAKeyGenParameterSpec.F4, pubKey.getPublicExponent());
      assertConsistency(pubKey, privKey);
    } catch (final RuntimeCryptoException e) {
      // Starting from version v1.35.1, AWS-LC built in FIPS mode allows key sizes larger than 4096.
      // This exception could happen if ACCP is built with a version of AWS-LC in FIPS mode that
      // does not support key sizes larger than 4096.
      assertTrue(TestUtil.isFips());
    }
  }

  @Test
  public void test_customE() throws GeneralSecurityException {
    final int[] bitLens = {4096, 5120};
    final BigInteger customE = RSAKeyGenParameterSpec.F4.add(BigInteger.valueOf(2));
    final KeyPairGenerator generator = getGenerator();

    for (int bitLen : bitLens) {
      if (TestUtil.isFips()) {
        assertThrows(
            InvalidAlgorithmParameterException.class,
            () -> generator.initialize(new RSAKeyGenParameterSpec(5120, customE)));
      } else {
        generator.initialize(new RSAKeyGenParameterSpec(bitLen, customE));
        final KeyPair keyPair = generator.generateKeyPair();
        final RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();
        final RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();
        assertEquals(bitLen, pubKey.getModulus().bitLength());
        assertEquals(customE, pubKey.getPublicExponent());
        assertConsistency(pubKey, privKey);
      }
    }
  }

  @Test
  public void threadStorm() throws Throwable {
    final byte[] rngSeed = TestUtil.getRandomBytes(20);
    System.out.println("RNG Seed: " + Hex.toHexString(rngSeed));
    final SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");
    rng.setSeed(rngSeed);
    final int generatorCount = 8;
    final int iterations = 250;
    final int threadCount = 48;

    final KeyPairGenerator[] generators = new KeyPairGenerator[generatorCount];
    for (int x = 0; x < generatorCount; x++) {
      generators[x] = KeyPairGenerator.getInstance("RSA", TestUtil.NATIVE_PROVIDER);
      if (!TestUtil.isFips()) {
        generators[x].initialize(1024);
      }
    }

    final List<TestThread> threads = new ArrayList<>();
    for (int x = 0; x < threadCount; x++) {
      threads.add(
          new TestThread("RsaGenThread-" + x, iterations, generators[rng.nextInt(generatorCount)]));
    }

    // Start the threads
    for (final TestThread t : threads) {
      t.start();
    }

    // Wait and collect the results
    final List<Throwable> results = new ArrayList<>();
    for (final TestThread t : threads) {
      t.join();
      if (t.result != null) {
        results.add(t.result);
      }
    }
    if (!results.isEmpty()) {
      final AssertionError ex = new AssertionError("Throwable while testing threads");
      for (Throwable t : results) {
        ex.addSuppressed(t);
      }
      throw ex;
    }
  }

  @Test
  public void separateDestruction() throws Exception {
    final KeyPairGenerator generator = getGenerator();
    generator.initialize(2048);
    final KeyPair keyPair = generator.generateKeyPair();
    testSeparateDestruction(keyPair);
  }

  static void testSeparateDestruction(final KeyPair kp) throws Exception {
    // Make sure that the keys are backed by the same native object.
    // Otherwise the test is invalid.
    assertEquals(
        EvpKeyFactoryTest.getRawPointer(kp.getPublic()),
        EvpKeyFactoryTest.getRawPointer(kp.getPrivate()),
        "Keys must be backed by same native object for test to be valid");
    // Destroy the private key
    kp.getPrivate().destroy();
    // Getting encoded private key must fail and mention destruction
    try {
      kp.getPrivate().getEncoded();
      fail("Expected exception");
    } catch (final IllegalStateException ex) {
      assertTrue(ex.getMessage().contains("destroy"), ex.getMessage());
    }
    // We must still be able to retrieve the public key
    final byte[] encoded = kp.getPublic().getEncoded();
    assertNotNull(encoded);
    assertTrue(encoded.length > 0);
    // Leading byte of an encoded key will never be zero
    assertTrue(encoded[0] != 0);
  }

  private static void assertConsistency(final RSAPublicKey pub, final RSAPrivateCrtKey priv)
      throws GeneralSecurityException {
    assertNotNull(pub);
    assertNotNull(priv);
    assertEquals(pub.getPublicExponent(), priv.getPublicExponent());
    assertNotNull(pub.getModulus());
    BigInteger modulus = priv.getModulus();
    assertEquals(pub.getModulus(), modulus);
    assertNotNull(priv.getPrivateExponent());
    assertNotNull(priv.getPrimeP());
    assertNotNull(priv.getPrimeQ());
    assertNotNull(priv.getPrimeExponentP());
    assertNotNull(priv.getPrimeExponentQ());
    assertNotNull(priv.getCrtCoefficient());

    // Do the underlying math
    final BigInteger p = priv.getPrimeP();
    final BigInteger q = priv.getPrimeQ();
    assertTrue(p.isProbablePrime(128));
    assertTrue(p.isProbablePrime(128));
    final BigInteger d = priv.getPrivateExponent();
    final BigInteger e = priv.getPublicExponent();
    final BigInteger dp = priv.getPrimeExponentP();
    final BigInteger dq = priv.getPrimeExponentQ();
    final BigInteger qInv = priv.getCrtCoefficient();

    final BigInteger p1 = p.subtract(BigInteger.ONE);
    final BigInteger q1 = q.subtract(BigInteger.ONE);

    assertEquals(modulus, p.multiply(q));
    assertEquals(d.mod(p1), dp);
    assertEquals(d.mod(q1), dq);
    assertEquals(q.modInverse(p), qInv);

    final BigInteger totient = p1.multiply(q1).divide(p1.gcd(q1));
    assertEquals(BigInteger.ONE, e.multiply(d).mod(totient));

    // Actually use the key
    final Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher.init(Cipher.ENCRYPT_MODE, pub);
    final byte[] ciphertext = cipher.doFinal(PLAINTEXT);
    cipher.init(Cipher.DECRYPT_MODE, priv);
    assertArrayEquals(PLAINTEXT, cipher.doFinal(ciphertext));
  }

  private static class TestThread extends Thread {
    private final KeyPairGenerator kg_;
    private final int iterations_;
    public volatile Throwable result = null;

    private TestThread(final String name, final int iterations, final KeyPairGenerator kg) {
      super(name);
      kg_ = kg;
      iterations_ = iterations;
    }

    @Override
    public void run() {
      for (int x = 0; x < iterations_; x++) {
        try {
          final KeyPair keyPair = kg_.generateKeyPair();
          assertConsistency(
              (RSAPublicKey) keyPair.getPublic(), (RSAPrivateCrtKey) keyPair.getPrivate());
        } catch (final Throwable t) {
          result = t;
          return;
        }
      }
    }
  }
}
