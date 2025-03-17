// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.benchmarks;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;

public class SignatureBase {
  protected KeyPair keyPair;
  protected Signature signer;
  protected Signature verifier;
  protected byte[] message = new byte[1024];
  protected byte[] signature;

  protected void setup(
          String provider,
          String keyAlg,
          AlgorithmParameterSpec keyParams,
          String sigAlg,
          AlgorithmParameterSpec sigParams)
          throws Exception {
    BenchmarkUtils.setupProvider(provider);
    final KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyAlg, provider);
    // Ed25519 in ACCP doesn't currently support initialization
    if (!keyAlg.equals("Ed25519") && !keyAlg.startsWith("ML-DSA")) {
      kpg.initialize(keyParams);
    }
    keyPair = kpg.generateKeyPair();
    signer = Signature.getInstance(sigAlg, provider);
    verifier = Signature.getInstance(sigAlg, provider);
    if (sigParams != null) {
      signer.setParameter(sigParams);
      verifier.setParameter(sigParams);
    }
    signer.initSign(keyPair.getPrivate());
    verifier.initVerify(keyPair.getPublic());
    new SecureRandom().nextBytes(message);
    signer.update(message);
    signature = signer.sign();
    verifier.update(message);
    if (!verifier.verify(signature)) {
      throw new RuntimeException("Verification failed in setup.");
    }
  }

  protected byte[] sign() throws Exception {
    signer.update(message);
    return signer.sign();
  }

  protected boolean verify() throws Exception {
    verifier.update(message);
    return verifier.verify(signature);
  }
}