// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Arrays;
import javax.crypto.KEM;
import javax.crypto.SecretKey;

/**
 * Round-trips an ML-KEM encapsulation through a release jar. Separate from {@link
 * ReleaseSmokeTest} because {@code javax.crypto.KEM} only exists on JDK17+: the main smoke test is
 * kept to Java 8 syntax so it compiles on every supported JDK, the same reason ACCP's own ML-KEM
 * support lives in a jdk17plus source overlay rather than the main source set.
 *
 * <p>Usage: java -cp AmazonCorrettoCryptoProvider.jar:. ReleaseSmokeTestMlKem
 */
public class ReleaseSmokeTestMlKem {
  private static final String PROVIDER_NAME = "AmazonCorrettoCryptoProvider";

  public static void main(String[] args) throws Exception {
    AmazonCorrettoCryptoProvider.install();
    AmazonCorrettoCryptoProvider accp = AmazonCorrettoCryptoProvider.INSTANCE;

    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-KEM-768", accp);
    KeyPair pair = keyGen.generateKeyPair();

    KEM kem = KEM.getInstance("ML-KEM-768", accp);
    KEM.Encapsulator encapsulator = kem.newEncapsulator(pair.getPublic());
    KEM.Encapsulated encapsulated = encapsulator.encapsulate();
    SecretKey encapsulatorSecret = encapsulated.key();

    KEM.Decapsulator decapsulator = kem.newDecapsulator(pair.getPrivate());
    SecretKey decapsulatorSecret = decapsulator.decapsulate(encapsulated.encapsulation());

    if (!Arrays.equals(encapsulatorSecret.getEncoded(), decapsulatorSecret.getEncoded())) {
      throw new AssertionError("ML-KEM-768 shared secret mismatch");
    }

    System.out.println("OK: ML-KEM-768 round trip via " + PROVIDER_NAME);
  }
}
