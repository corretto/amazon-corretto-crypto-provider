// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

public enum MlKemParameter {
    // (parameterSize, publicKeySize, secretKeySize, ciphertextSize) - constants defined in AWS-LC
    MLKEM_512(512, 800, 1632, 768),
    MLKEM_768(768, 1184, 2400, 1088),
    MLKEM_1024(1024, 1568, 3168, 1568);

    private final int parameterSize;
    private final int publicKeySize;
    private final int secretKeySize;
    private final int ciphertextSize;

    MlKemParameter(int parameterSize, int publicKeySize, int secretKeySize, int ciphertextSize) {
        this.parameterSize = parameterSize;
        this.publicKeySize = publicKeySize;
        this.secretKeySize = secretKeySize;
        this.ciphertextSize = ciphertextSize;
    }

    public static MlKemParameter fromParameterSize(int parameterSet) {
        for (MlKemParameter param : values()) {
            if (param.parameterSize == parameterSet) {
                return param;
            }
        }
        throw new IllegalArgumentException("Invalid ML-KEM parameter set: " + parameterSet);
    }

    public int getPublicKeySize() { return publicKeySize; }
    public int getSecretKeySize() { return secretKeySize; }
    public int getCiphertextSize() { return ciphertextSize; }
    public int getParameterSize() { return parameterSize; }

   
    public String getAlgorithmName() { 
        return "ML-KEM-" + parameterSize; 
    }

    // Shared secret size is constant across all parameter sets for ML-KEM
    public static final int SHARED_SECRET_SIZE = 32;
}
