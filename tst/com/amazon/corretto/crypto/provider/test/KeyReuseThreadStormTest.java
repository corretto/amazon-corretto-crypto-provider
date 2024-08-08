// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.NATIVE_PROVIDER;
import static com.amazon.corretto.crypto.provider.test.TestUtil.assertArraysHexEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Supplier;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledForJreRange;
import org.junit.jupiter.api.condition.JRE;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.SAME_THREAD)
@ResourceLock(value = TestUtil.RESOURCE_REFLECTION)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ_WRITE)
public class KeyReuseThreadStormTest {
  private static final KeyPairGenerator RSA_KEY_GEN;
  private static final KeyPairGenerator EC_KEY_GEN;
  private static final KeyPairGenerator ED_KEY_GEN;
  private static final KeyPair PAIR_RSA_1024_OR_DEFAULT;
  private static final KeyPair PAIR_RSA_2048;
  private static final KeyPair PAIR_RSA_4096;
  private static final KeyPair PAIR_EC_P256;
  private static final KeyPair PAIR_EC_P384;
  private static final KeyPair PAIR_EC_P521;
  private static final KeyPair PAIR_ED25519;

  static {
    try {
      RSA_KEY_GEN = KeyPairGenerator.getInstance("RSA", NATIVE_PROVIDER);
      if (!TestUtil.isFips()) {
        RSA_KEY_GEN.initialize(1024);
      }
      PAIR_RSA_1024_OR_DEFAULT = RSA_KEY_GEN.generateKeyPair();
      RSA_KEY_GEN.initialize(2048);
      PAIR_RSA_2048 = RSA_KEY_GEN.generateKeyPair();
      RSA_KEY_GEN.initialize(4096);
      PAIR_RSA_4096 = RSA_KEY_GEN.generateKeyPair();
      EC_KEY_GEN = KeyPairGenerator.getInstance("EC", NATIVE_PROVIDER);
      EC_KEY_GEN.initialize(new ECGenParameterSpec("NIST P-256"));
      PAIR_EC_P256 = EC_KEY_GEN.generateKeyPair();
      EC_KEY_GEN.initialize(new ECGenParameterSpec("NIST P-384"));
      PAIR_EC_P384 = EC_KEY_GEN.generateKeyPair();
      EC_KEY_GEN.initialize(new ECGenParameterSpec("NIST P-521"));
      PAIR_EC_P521 = EC_KEY_GEN.generateKeyPair();
      ED_KEY_GEN =
          TestUtil.getJavaVersion() >= 15
              ? KeyPairGenerator.getInstance("Ed25519", NATIVE_PROVIDER)
              : null;
      PAIR_ED25519 = TestUtil.getJavaVersion() >= 15 ? ED_KEY_GEN.generateKeyPair() : null;
    } catch (final GeneralSecurityException ex) {
      throw new AssertionError(ex);
    }
  }

  @Test
  public void aesThreadStorm() throws Throwable {
    final byte[] rngSeed = TestUtil.getRandomBytes(20);
    System.out.println("RNG Seed: " + Arrays.toString(rngSeed));
    final SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");
    rng.setSeed(rngSeed);
    final int iterations = 500;
    final int threadCount = 48;

    final SecretKey[] keys = new SecretKey[3];
    byte[] buff = new byte[32];
    rng.nextBytes(buff);
    keys[0] = new SecretKeySpec(buff, 0, 16, "AES");
    keys[1] = new SecretKeySpec(buff, 0, 24, "AES");
    keys[2] = new SecretKeySpec(buff, 0, 32, "AES");

    final List<TestThread> threads = new ArrayList<>();
    for (int x = 0; x < threadCount; x++) {
      final List<SecretKey> keyList = new ArrayList<>(3);
      while (keyList.isEmpty()) {
        for (int k = 0; k < keys.length; k++) {
          if (rng.nextBoolean()) {
            keyList.add(keys[k]);
          }
        }
      }
      final TestThread t;
      final Supplier<AlgorithmParameterSpec> gcmParamSpecSupplier =
          () -> {
            return new GCMParameterSpec(128, TestUtil.getRandomBytes(12));
          };
      if (x % 2 == 0) {
        t =
            new SymmCipherTestThread(
                "AesGcmCipherThread-" + x,
                rng,
                iterations,
                "AES/GCM/NoPadding",
                keyList,
                gcmParamSpecSupplier);
      } else {
        if (rng.nextInt(2) == 0) {
          t =
              new SymmCipherTestThread(
                  "AesKwpSymmCipherThread-" + x,
                  rng,
                  iterations,
                  "AES/KWP/NoPadding",
                  keyList,
                  () -> null);
        } else {
          t =
              new WrapCipherTestThread(
                  "AesKwpWrapCipherThread-" + x, rng, iterations, "AES/KWP/NoPadding", keyList);
        }
      }
      threads.add(t);
    }
    executeThreads(threads);
  }

  @Test
  public void rsaThreadStorm() throws Throwable {
    final byte[] rngSeed = TestUtil.getRandomBytes(20);
    System.out.println("RNG Seed: " + Arrays.toString(rngSeed));
    final SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");
    rng.setSeed(rngSeed);
    final int iterations = 500;
    final int threadCount = 48;

    final List<TestThread> threads = new ArrayList<>();
    for (int x = 0; x < threadCount; x++) {
      final List<KeyPair> keys = new ArrayList<KeyPair>();
      while (keys.isEmpty()) {
        if (rng.nextBoolean()) {
          keys.add(PAIR_RSA_1024_OR_DEFAULT);
        }
        if (rng.nextBoolean()) {
          keys.add(PAIR_RSA_2048);
        }
        if (rng.nextBoolean()) {
          keys.add(PAIR_RSA_4096);
        }
      }
      final TestThread t;
      if (x % 2 == 0) {
        t =
            new AsymmCipherTestThread(
                "RsaCipherThread-" + x,
                rng,
                iterations,
                "RSA/ECB/OAEPWithSHA-1AndMGF1Padding",
                keys);
      } else {
        t = new SignatureTestThread("RsaSignatureThread-" + x, rng, iterations, "RSASSA-PSS", keys);
      }
      threads.add(t);
    }
    executeThreads(threads);
  }

  @Test
  public void ecThreadStorm() throws Throwable {
    final byte[] rngSeed = TestUtil.getRandomBytes(20);
    System.out.println("RNG Seed: " + Arrays.toString(rngSeed));
    final SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");
    rng.setSeed(rngSeed);
    final int generatorCount = 8;
    final int iterations = 500;
    final int threadCount = 48;

    final List<TestThread> threads = new ArrayList<>();
    for (int x = 0; x < threadCount; x++) {
      final List<KeyPair> keys = new ArrayList<KeyPair>();
      while (keys.size() < 2) {
        if (rng.nextBoolean()) {
          keys.add(PAIR_EC_P256);
        }
        if (rng.nextBoolean()) {
          keys.add(PAIR_EC_P384);
        }
        if (rng.nextBoolean()) {
          keys.add(PAIR_EC_P521);
        }
      }
      final TestThread t;
      if (x % 2 == 0) {
        t = new SignatureTestThread("EcdsaThread-" + x, rng, iterations, "NONEwithECDSA", keys);
      } else {
        t = new KeyAgreementThread("EcdhThread-" + x, rng, iterations, "ECDH", keys);
      }
      threads.add(t);
    }
    executeThreads(threads);
  }

  @Test
  @EnabledForJreRange(min = JRE.JAVA_15)
  public void edThreadStorm() throws Throwable {
    final byte[] rngSeed = TestUtil.getRandomBytes(20);
    System.out.println("RNG Seed: " + Arrays.toString(rngSeed));
    final SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");
    rng.setSeed(rngSeed);
    final int iterations = 500;
    final int threadCount = 48;

    final List<TestThread> threads = new ArrayList<>();
    for (int x = 0; x < threadCount; x++) {
      final List<KeyPair> keys = new ArrayList<KeyPair>();
      while (keys.size() < 2) {
        keys.add(PAIR_ED25519);
      }
      final TestThread t;
      t = new SignatureTestThread("EddsaThread-" + x, rng, iterations, "Ed25519", keys);
      threads.add(t);
    }
    executeThreads(threads);
  }

  private abstract static class TestThread extends Thread {
    public volatile Throwable result = null;
    protected final SecureRandom rnd_;
    protected final int iterations_;
    protected final byte[] message_ = new byte[64];

    public abstract void run();

    public TestThread(String name, SecureRandom rng, int iterations)
        throws GeneralSecurityException {
      super(name);
      iterations_ = iterations;
      final byte[] seed = new byte[20];
      rng.nextBytes(seed);
      rnd_ = SecureRandom.getInstance("SHA1PRNG");
      rnd_.setSeed(seed);
      rnd_.nextBytes(message_);
    }
  }

  private abstract static class CipherTestThread extends TestThread {
    protected final Cipher enc_;
    protected final Cipher dec_;

    public CipherTestThread(String name, SecureRandom rng, int iterations, String transform)
        throws GeneralSecurityException {
      super(name, rng, iterations);
      enc_ = Cipher.getInstance(transform, NATIVE_PROVIDER);
      dec_ = Cipher.getInstance(transform, NATIVE_PROVIDER);
    }
  }

  private static class WrapCipherTestThread extends CipherTestThread {
    private final List<SecretKey> keys_;
    private final Key key_;

    public WrapCipherTestThread(
        String name, SecureRandom rng, int iterations, String transform, List<SecretKey> keys)
        throws GeneralSecurityException {
      super(name, rng, iterations, transform);
      keys_ = keys;
      final byte[] keyBytes = new byte[32];
      rnd_.nextBytes(keyBytes);
      key_ = new SecretKeySpec(keyBytes, "Generic");
    }

    @Override
    public void run() {
      for (int x = 0; x < iterations_; x++) {
        try {
          final SecretKey kek = keys_.get(rnd_.nextInt(keys_.size()));
          enc_.init(Cipher.WRAP_MODE, kek);
          dec_.init(Cipher.UNWRAP_MODE, kek);
          assertArraysHexEquals(
              key_.getEncoded(),
              dec_.unwrap(enc_.wrap(key_), "Generic", Cipher.SECRET_KEY).getEncoded());
        } catch (final Throwable ex) {
          result = ex;
          return;
        }
      }
    }
  }

  private static class AsymmCipherTestThread extends CipherTestThread {
    private final List<KeyPair> keyPairs_;

    public AsymmCipherTestThread(
        String name, SecureRandom rng, int iterations, String transform, List<KeyPair> keyPairs)
        throws GeneralSecurityException {
      super(name, rng, iterations, transform);
      keyPairs_ = keyPairs;
    }

    @Override
    public void run() {
      for (int x = 0; x < iterations_; x++) {
        try {
          final KeyPair pair = keyPairs_.get(rnd_.nextInt(keyPairs_.size()));
          enc_.init(Cipher.ENCRYPT_MODE, pair.getPublic(), rnd_);
          dec_.init(Cipher.DECRYPT_MODE, pair.getPrivate(), rnd_);
          assertArraysHexEquals(message_, dec_.doFinal(enc_.doFinal(message_)));
        } catch (final Throwable ex) {
          result = ex;
          return;
        }
      }
    }
  }

  private static class SymmCipherTestThread extends CipherTestThread {
    private final List<SecretKey> keys_;
    private final Supplier<AlgorithmParameterSpec> paramSpecSupplier_;

    public SymmCipherTestThread(
        String name,
        SecureRandom rng,
        int iterations,
        String transform,
        List<SecretKey> keys,
        Supplier<AlgorithmParameterSpec> paramSpecSupplier)
        throws GeneralSecurityException {
      super(name, rng, iterations, transform);
      keys_ = keys;
      paramSpecSupplier_ = paramSpecSupplier;
    }

    @Override
    public void run() {
      for (int x = 0; x < iterations_; x++) {
        try {
          final SecretKey key = keys_.get(rnd_.nextInt(keys_.size()));
          final AlgorithmParameterSpec spec = paramSpecSupplier_.get();
          enc_.init(Cipher.ENCRYPT_MODE, key, spec, rnd_);
          dec_.init(Cipher.DECRYPT_MODE, key, spec, rnd_);
          assertArraysHexEquals(message_, dec_.doFinal(enc_.doFinal(message_)));
        } catch (final Throwable ex) {
          result = ex;
          return;
        }
      }
    }
  }

  private static class SignatureTestThread extends TestThread {
    private final Signature sign_;
    private final Signature verify_;
    private final List<KeyPair> keyPairs_;

    public SignatureTestThread(
        String name, SecureRandom rng, int iterations, String transform, List<KeyPair> keyPairs)
        throws GeneralSecurityException {
      super(name, rng, iterations);
      sign_ = Signature.getInstance(transform, NATIVE_PROVIDER);
      verify_ = Signature.getInstance(transform, NATIVE_PROVIDER);
      keyPairs_ = keyPairs;
    }

    @Override
    public void run() {
      for (int x = 0; x < iterations_; x++) {
        try {
          final KeyPair pair = keyPairs_.get(rnd_.nextInt(keyPairs_.size()));
          sign_.initSign(pair.getPrivate(), rnd_);
          verify_.initVerify(pair.getPublic());
          sign_.update(message_);
          verify_.update(message_);
          assertTrue(verify_.verify(sign_.sign()));
        } catch (final Throwable ex) {
          result = ex;
          return;
        }
      }
    }
  }

  private static class KeyAgreementThread extends TestThread {
    private final KeyAgreement alice_;
    private final KeyAgreement bob_;
    private final List<KeyPair> keyPairs_;

    public KeyAgreementThread(
        String name, SecureRandom rng, int iterations, String transform, List<KeyPair> keyPairs)
        throws GeneralSecurityException {
      super(name, rng, iterations);
      alice_ = KeyAgreement.getInstance(transform, NATIVE_PROVIDER);
      bob_ = KeyAgreement.getInstance(transform, NATIVE_PROVIDER);
      keyPairs_ = keyPairs;
    }

    @Override
    public void run() {
      for (int x = 0; x < iterations_; x++) {
        try {
          final KeyPair kpA = keyPairs_.get(rnd_.nextInt(keyPairs_.size()));
          final KeyPair kpB = kpA;
          alice_.init(kpA.getPrivate(), rnd_);
          bob_.init(kpB.getPrivate(), rnd_);
          alice_.doPhase(kpB.getPublic(), /*lastPhase*/ true);
          bob_.doPhase(kpA.getPublic(), /*lastPhase*/ true);
          assertArraysHexEquals(alice_.generateSecret(), bob_.generateSecret());
        } catch (final Throwable ex) {
          result = ex;
          return;
        }
      }
    }
  }

  private static void executeThreads(List<TestThread> threads) throws InterruptedException {
    for (final TestThread t : threads) {
      t.start();
    }
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
        t.printStackTrace();
        ex.addSuppressed(t);
      }
      throw ex;
    }
  }
}
