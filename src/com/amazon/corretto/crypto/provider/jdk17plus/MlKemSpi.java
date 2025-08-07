// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

abstract class MlKemSpi implements KEMSpi {

  protected final MlKemParameter parameterSet;
  protected final int publicKeySize;
  protected final int privateKeySize;
  protected final int ciphertextSize;

  private static native void nativeEncapsulate(
      long evpKeyPtr, byte[] ciphertext, byte[] sharedSecret);

  private static native void nativeDecapsulate(
      long evpKeyPtr, byte[] ciphertext, byte[] sharedSecret);

  protected MlKemSpi(MlKemParameter parameterSet) {
    Loader.checkNativeLibraryAvailability();
    this.parameterSet = parameterSet;
    this.publicKeySize = parameterSet.getPublicKeySize();
    this.privateKeySize = parameterSet.getSecretKeySize();
    this.ciphertextSize = parameterSet.getCiphertextSize();
  }

  @Override
  public KEMSpi.EncapsulatorSpi engineNewEncapsulator(
      PublicKey publicKey, AlgorithmParameterSpec spec, SecureRandom secureRandom)
      throws InvalidAlgorithmParameterException, InvalidKeyException {

    if (publicKey == null) {
      throw new InvalidKeyException("Public key cannot be null");
    }
    if (secureRandom != null) {
      throw new InvalidAlgorithmParameterException(
          "SecureRandom must be null - AWS-LC handles its own randomness");
    }
    if (!(publicKey instanceof EvpKemPublicKey)) {
      throw new InvalidKeyException("Unsupported public key type");
    }

    EvpKemPublicKey kemKey = (EvpKemPublicKey) publicKey;
    KemUtils.validateParameterSpec(spec, kemKey);
    return new MlKemEncapsulatorSpi(kemKey, ciphertextSize);
  }

  @Override
  public KEMSpi.DecapsulatorSpi engineNewDecapsulator(
      PrivateKey privateKey, AlgorithmParameterSpec spec)
      throws InvalidAlgorithmParameterException, InvalidKeyException {

    if (privateKey == null) {
      throw new InvalidKeyException("Private key cannot be null");
    }
    if (!(privateKey instanceof EvpKemPrivateKey)) {
      throw new InvalidKeyException("Unsupported private key type");
    }

    EvpKemPrivateKey kemKey = (EvpKemPrivateKey) privateKey;
    KemUtils.validateParameterSpec(spec, kemKey);
    return new MlKemDecapsulatorSpi(kemKey, ciphertextSize);
  }

  public static final class MlKem512 extends MlKemSpi {
    public MlKem512() {
      super(MlKemParameter.MLKEM_512);
    }
  }

  public static final class MlKem768 extends MlKemSpi {
    public MlKem768() {
      super(MlKemParameter.MLKEM_768);
    }
  }

  public static final class MlKem1024 extends MlKemSpi {
    public MlKem1024() {
      super(MlKemParameter.MLKEM_1024);
    }
  }

  private static class MlKemEncapsulatorSpi implements KEMSpi.EncapsulatorSpi {
    private final EvpKemPublicKey publicKey;
    private final int ciphertextSize;

    MlKemEncapsulatorSpi(EvpKemPublicKey publicKey, int ciphertextSize) {
      this.publicKey = publicKey;
      this.ciphertextSize = ciphertextSize;
    }

    @Override
    public KEM.Encapsulated engineEncapsulate(int from, int to, String algorithm) {
      if (from < 0 || from > to || to > MlKemParameter.SHARED_SECRET_SIZE) {
        throw new IndexOutOfBoundsException("Invalid range: from=" + from + ", to=" + to);
      }
      if (!("ML-KEM".equals(algorithm) || "Generic".equals(algorithm))) {
        throw new UnsupportedOperationException(
            "Only ML-KEM algorithm is supported, got: " + algorithm);
      }
      if (from != 0 || to != MlKemParameter.SHARED_SECRET_SIZE) {
        throw new UnsupportedOperationException("Only full secret size is supported");
      }

      return publicKey.use(
          ptr -> {
            byte[] ciphertext = new byte[ciphertextSize];
            // shared secret size of ML-KEM is always 32 bytes regardless of parameter set
            byte[] sharedSecret = new byte[MlKemParameter.SHARED_SECRET_SIZE];

            nativeEncapsulate(ptr, ciphertext, sharedSecret);
            return new KEM.Encapsulated(
                new SecretKeySpec(sharedSecret, algorithm), ciphertext, null);
          });
    }

    @Override
    public int engineSecretSize() {
      return MlKemParameter.SHARED_SECRET_SIZE;
    }

    @Override
    public int engineEncapsulationSize() {
      return ciphertextSize;
    }
  }

  private static class MlKemDecapsulatorSpi implements KEMSpi.DecapsulatorSpi {
    private final EvpKemPrivateKey privateKey;
    private final int ciphertextSize;

    MlKemDecapsulatorSpi(EvpKemPrivateKey privateKey, int ciphertextSize) {
      this.privateKey = privateKey;
      this.ciphertextSize = ciphertextSize;
    }

    @Override
    public SecretKey engineDecapsulate(byte[] encapsulation, int from, int to, String algorithm)
        throws DecapsulateException {
      if (encapsulation == null) {
        throw new NullPointerException("Encapsulation cannot be null");
      }
      if (from < 0 || from > to || to > MlKemParameter.SHARED_SECRET_SIZE) {
        throw new IndexOutOfBoundsException("Invalid range: from=" + from + ", to=" + to);
      }

      return privateKey.use(
          ptr -> {
            // shared secret size of ML-KEM is always 32 bytes regardless of parameter set
            byte[] sharedSecret = new byte[MlKemParameter.SHARED_SECRET_SIZE];
            nativeDecapsulate(ptr, encapsulation, sharedSecret);
            return new SecretKeySpec(sharedSecret, algorithm);
          });
    }

    @Override
    public int engineSecretSize() {
      return MlKemParameter.SHARED_SECRET_SIZE;
    }

    @Override
    public int engineEncapsulationSize() {
      return ciphertextSize;
    }
  }
}
