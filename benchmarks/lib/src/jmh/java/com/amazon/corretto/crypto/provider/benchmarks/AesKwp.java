// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.benchmarks;

import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

@State(Scope.Benchmark)
public class AesKwp {
  private static final int GENERIC_KEY_SIZE = 1024;
  private static final int RSA_BITS = 2048;
  private static final String CURVE = "secp256r1";

  @Param({"128"})
  public int kekBits;

  @Param({AmazonCorrettoCryptoProvider.PROVIDER_NAME, "BC", "SunJCE"})
  public String provider;

  protected Key kek;
  protected Cipher wrapper;
  protected Cipher unwrapper;
  private Key unwrappedSymmetricKey;
  private byte[] wrappedSymmetricKey;
  private Key unwrappedRsaKey;
  private byte[] wrappedRsaKey;
  private Key unwrappedEcKey;
  private byte[] wrappedEcKey;

  @Setup
  public void setup() throws Exception {
    BenchmarkUtils.setupProvider(provider);
    kek = new SecretKeySpec(BenchmarkUtils.getRandBytes(kekBits / 8), "AES");
    // Bouncy Castle and SunJCE have wierd names for this...
    String algorithm = "AES/KWP/NoPadding";
    if ("BC".equals(provider)) {
      algorithm = "AESKWP";
    } else if ("SunJCE".equals(provider)) {
      algorithm = "AESWRAPPAD";
    }
    wrapper = Cipher.getInstance(algorithm, provider);
    unwrapper = Cipher.getInstance(algorithm, provider);

    wrapper.init(Cipher.WRAP_MODE, kek);
    unwrappedSymmetricKey =
        new SecretKeySpec(BenchmarkUtils.getRandBytes(GENERIC_KEY_SIZE), "Generic");
    wrappedSymmetricKey = wrapper.wrap(unwrappedSymmetricKey);

    String rsaProvider = provider;
    String ecProvider = provider;
    if (provider.equals("SunJCE")) {
      rsaProvider = "SunRsaSign";
      ecProvider = "SunEC";
    }

    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", rsaProvider);
    kpg.initialize(new RSAKeyGenParameterSpec(RSA_BITS, RSAKeyGenParameterSpec.F4));
    unwrappedRsaKey = kpg.generateKeyPair().getPrivate();
    wrapper.init(Cipher.WRAP_MODE, kek);
    wrappedRsaKey = wrapper.wrap(unwrappedRsaKey);

    // SunJCE seems to have somewhat spotty impls. for secp256r1. if not
    // found, set to null so the relevant EC benchmarks are skipped without
    // interfering with the others.
    try {
      kpg = KeyPairGenerator.getInstance("EC", ecProvider);
    } catch (NoSuchAlgorithmException e) {
      wrappedEcKey = null;
      return;
    }
    kpg.initialize(new ECGenParameterSpec(CURVE));
    unwrappedEcKey = kpg.generateKeyPair().getPrivate();
    wrapper.init(Cipher.WRAP_MODE, kek);
    wrappedEcKey = wrapper.wrap(unwrappedEcKey);
  }

  @Benchmark
  public byte[] wrapSymmetric() throws Exception {
    wrapper.init(Cipher.WRAP_MODE, kek);
    return wrapper.wrap(unwrappedSymmetricKey);
  }

  @Benchmark
  public Key unwrapSymmetric() throws Exception {
    unwrapper.init(Cipher.UNWRAP_MODE, kek);
    return unwrapper.unwrap(wrappedSymmetricKey, "Generic", Cipher.SECRET_KEY);
  }

  @Benchmark
  public byte[] wrapRsa() throws Exception {
    wrapper.init(Cipher.WRAP_MODE, kek);
    return wrapper.wrap(unwrappedRsaKey);
  }

  @Benchmark
  public Key unwrapRsa() throws Exception {
    unwrapper.init(Cipher.UNWRAP_MODE, kek);
    return unwrapper.unwrap(wrappedRsaKey, "RSA", Cipher.PRIVATE_KEY);
  }

  @Benchmark
  public byte[] wrapEc() throws Exception {
    wrapper.init(Cipher.WRAP_MODE, kek);
    return wrapper.wrap(unwrappedEcKey);
  }

  @Benchmark
  public Key unwrapEc() throws Exception {
    unwrapper.init(Cipher.UNWRAP_MODE, kek);
    return unwrapper.unwrap(wrappedEcKey, "EC", Cipher.PRIVATE_KEY);
  }
}
