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
   * @param key the parameter set of the given
   * @throws InvalidAlgorithmParameterException if spec is null, wrong type, or incompatible with
   *     key
   */
  private static void validateParameterSpec(AlgorithmParameterSpec spec, String parameterSet)
      throws InvalidAlgorithmParameterException {

    if (spec == null) {
      throw new InvalidAlgorithmParameterException("Please pass in a non-null parameter spec.");
    }
    if (!(spec instanceof NamedParameterSpec)) {
      throw new InvalidAlgorithmParameterException("ACCP can only accept NamedParameterSpec");
    }

    NamedParameterSpec namedSpec = (NamedParameterSpec) spec;
    if (!namedSpec.getName().equals(parameterSet)) {
      throw new InvalidAlgorithmParameterException(
          "Unsupported parameters. Please use valid parameters");
    }
  }

  /**
   * Validates that the algorithm is supported for ML-KEM operations.
   *
   * @param algorithm the algorithm name to validate
   * @param algorithm the algorithm name to validate (must be "Generic", "ML-KEM", or match the
   *     parameter set)
   * @throws UnsupportedOperationException if the algorithm is not supported
   */
  private static void validateAlgorithm(String algorithm, String parameterSetAlgorithmName) {
    if (!"Generic".equals(algorithm)
        && !"ML-KEM".equals(algorithm)
        && !parameterSetAlgorithmName.equals(algorithm)) {
      throw new UnsupportedOperationException(
          "Only Generic, ML-KEM, or "
              + parameterSetAlgorithmName
              + " algorithm is supported, got: "
              + algorithm);
    }
  }

  @Override
  public KEMSpi.EncapsulatorSpi engineNewEncapsulator(
      PublicKey publicKey, AlgorithmParameterSpec spec, SecureRandom secureRandom)
      throws InvalidAlgorithmParameterException, InvalidKeyException {

    if (publicKey == null) {
      throw new InvalidKeyException("Public key cannot be null");
    }

    // AWS-LC handles randomness for ML-KEM
    if (secureRandom != null) {
      throw new InvalidAlgorithmParameterException(
          "SecureRandom must be null - AWS-LC handles its own randomness");
    }
    if (!(publicKey instanceof EvpKemPublicKey)) {
      throw new InvalidKeyException("Unsupported public key type");
    }

    EvpKemPublicKey kemKey = (EvpKemPublicKey) publicKey;
    String keyParamSetName = kemKey.getParameterSet().getAlgorithmName();
    validateParameterSpec(spec, keyParamSetName);

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
    String keyParamSetName = kemKey.getParameterSet().getAlgorithmName();
    validateParameterSpec(spec, keyParamSetName);

    return new MlKemDecapsulatorSpi(kemKey, kemKey.getParameterSet());
  }

  public static final class MlKemSpi512 extends MlKemSpi {
    public MlKemSpi512() {
      super(MlKemParameter.MLKEM_512);
    }
  }

  public static final class MlKemSpi768 extends MlKemSpi {
    public MlKemSpi768() {
      super(MlKemParameter.MLKEM_768);
    }
  }

  public static final class MlKemSpi1024 extends MlKemSpi {
    public MlKemSpi1024() {
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
      Objects.requireNonNull(algorithm, "Please specify an algorithm.");
      validateAlgorithm(algorithm, parameterSet.getAlgorithmName());

      // ACCP currently only supports full shared secret extraction
      if (from != 0 || to != engineSecretSize()) {
        throw new UnsupportedOperationException(
            "ACCP only supports extracting the full shared secret. ML-KEM's shared secret size is"
                + " always 32 bytes.");
      }

      byte[] ciphertext = new byte[engineEncapsulationSize()];
      byte[] sharedSecret = new byte[engineSecretSize()];
      publicKey.useVoid(ptr -> nativeEncapsulate(ptr, ciphertext, sharedSecret));
      return new KEM.Encapsulated(new SecretKeySpec(sharedSecret, algorithm), ciphertext, null);
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
      Objects.requireNonNull(algorithm);
      Objects.requireNonNull(encapsulation);
      validateAlgorithm(algorithm, parameterSet.getAlgorithmName());

      if (encapsulation.length != engineEncapsulationSize()) {
        throw new DecapsulateException("The size of the encapsulation is invalid.");
      }

      byte[] sharedSecret = new byte[engineSecretSize()];
      privateKey.useVoid(ptr -> nativeDecapsulate(ptr, encapsulation, sharedSecret));
      return new SecretKeySpec(sharedSecret, algorithm);
    }

    @Override
    public int engineSecretSize() {
      // shared secret size of ML-KEM is always 32 bytes regardless of parameter set
      return MlKemParameter.SHARED_SECRET_SIZE;
    }

    @Override
    public int engineEncapsulationSize() {
      return parameterSet.getCiphertextSize();
    }
  }
}
