// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.Objects;
import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

abstract class MlKemSpi implements KEMSpi {

  protected final MlKemParameter parameterSet;

  private static native void nativeEncapsulate(
      long evpKeyPtr, byte[] ciphertext, byte[] sharedSecret);

  private static native void nativeDecapsulate(
      long evpKeyPtr, byte[] ciphertext, byte[] sharedSecret);

  protected MlKemSpi(MlKemParameter parameterSet) {
    Loader.checkNativeLibraryAvailability();
    this.parameterSet = parameterSet;
  }

  /**
   * Validates that a NamedParameterSpec is compatible with the given ML-KEM key. Ensures the spec's
   * algorithm name matches the key's parameter set.
   *
   * @param spec the algorithm parameter spec (must not be null)
   * @param key the ML-KEM key to validate against
   * @throws InvalidAlgorithmParameterException if spec is null, wrong type, or incompatible with
   *     key
   */
  private static void validateParameterSpec(AlgorithmParameterSpec spec, EvpKemKey key)
      throws InvalidAlgorithmParameterException {

    if (spec == null) {
      throw new InvalidAlgorithmParameterException("Please pass in a non-null parameter spec.");
    }
    if (spec instanceof NamedParameterSpec) {
      NamedParameterSpec namedSpec = (NamedParameterSpec) spec;

      String keyParamSetName = key.getParameterSet().getAlgorithmName();
      if (!(namedSpec.getName().equals(keyParamSetName))) {
        throw new InvalidAlgorithmParameterException(
            "Parameter spec mismatch. Expected: "
                + keyParamSetName
                + ", but got: "
                + namedSpec.getName());
      }
    } else {
      throw new InvalidAlgorithmParameterException(
          "Unsupported parameter spec type: " + spec.getClass().getName());
    }
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
    validateParameterSpec(spec, kemKey);
    return new MlKemEncapsulatorSpi(kemKey, kemKey.getParameterSet());
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
    validateParameterSpec(spec, kemKey);
    return new MlKemDecapsulatorSpi(kemKey, kemKey.getParameterSet());
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
    private final MlKemParameter parameterSet;

    MlKemEncapsulatorSpi(EvpKemPublicKey publicKey, MlKemParameter parameterSet) {
      this.publicKey = publicKey;
      this.parameterSet = parameterSet;
    }

    @Override
    public KEM.Encapsulated engineEncapsulate(int from, int to, String algorithm) {

      Objects.checkFromToIndex(from, to, engineSecretSize());

      // Only support full shared secret extraction
      if (from != 0 || to != engineSecretSize()) {
        throw new UnsupportedOperationException("Only full secret size is supported");
      }

      // if algorithm is Generic then use the key's parameter set
      String keyAlgorithm =
          "Generic".equals(algorithm) ? parameterSet.getAlgorithmName() : algorithm;

      if (!("ML-KEM".equals(keyAlgorithm)
          || "Generic".equals(algorithm)
          || parameterSet.getAlgorithmName().equals(keyAlgorithm))) {
        throw new UnsupportedOperationException(
            "Only ML-KEM algorithm is supported, got: " + algorithm);
      }

      byte[] ciphertext = new byte[engineEncapsulationSize()];
      byte[] sharedSecret =
          new byte
              [engineSecretSize()]; // shared secret size of ML-KEM is always 32 bytes regardless
      // of parameter set
      return publicKey.use(
          ptr -> {
            nativeEncapsulate(ptr, ciphertext, sharedSecret);
            return new KEM.Encapsulated(
                new SecretKeySpec(sharedSecret, keyAlgorithm), ciphertext, null);
          });
    }

    @Override
    public int engineSecretSize() {
      return MlKemParameter.SHARED_SECRET_SIZE;
    }

    @Override
    public int engineEncapsulationSize() {
      return parameterSet.getCiphertextSize();
    }
  }

  private static class MlKemDecapsulatorSpi implements KEMSpi.DecapsulatorSpi {
    private final EvpKemPrivateKey privateKey;
    private final MlKemParameter parameterSet;

    MlKemDecapsulatorSpi(EvpKemPrivateKey privateKey, MlKemParameter parameterSet) {
      this.privateKey = privateKey;
      this.parameterSet = parameterSet;
    }

    @Override
    public SecretKey engineDecapsulate(byte[] encapsulation, int from, int to, String algorithm)
        throws DecapsulateException {

      Objects.checkFromToIndex(from, to, engineSecretSize());
      if (encapsulation == null) {
        throw new NullPointerException("Encapsulation cannot be null");
      }

      // if algorithm is Generic then use parameterSet algorithm name to wrap key
      String keyAlgorithm =
          "Generic".equals(algorithm) ? parameterSet.getAlgorithmName() : algorithm;

      // shared secret size of ML-KEM is always 32 bytes regardless of parameter set
      byte[] sharedSecret = new byte[engineSecretSize()];

      return privateKey.use(
          ptr -> {
            nativeDecapsulate(ptr, encapsulation, sharedSecret);
            return new SecretKeySpec(sharedSecret, keyAlgorithm);
          });
    }

    @Override
    public int engineSecretSize() {
      return MlKemParameter.SHARED_SECRET_SIZE;
    }

    @Override
    public int engineEncapsulationSize() {
      return parameterSet.getCiphertextSize();
    }
  }
}
