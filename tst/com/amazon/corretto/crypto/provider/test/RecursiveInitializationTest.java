// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import javax.crypto.Cipher;
import org.bouncycastle.crypto.prng.BasicEntropySourceProvider;

/**
 * This test is a special case - it tests a recursive initialization path that looks like:
 *
 * <p>ACCP.[ctor] -> Self tests -> Mac.getInstance -> JceSecurity.[static init] ->
 * SecureRandom.[ctor] -> BouncyCastle.createBaseRandom -> LibCryptoRng.[ctor] -> NJCE.[ctor] ->
 * Self tests -> Mac.getInstance -> JceSecurity (uninitialized)
 *
 * <p>As this path only occurs when static initializers for JceSecurity are incomplete, it _must_
 * run on a fresh JVM to be an effective test. As such it's run outside of junit, as a bare java
 * executable.
 *
 * <p>The code for this test is based on the Trent JceProviderLoader.
 */
public class RecursiveInitializationTest {
  public static void main(String[] args) throws Exception {
    load();
  }

  // Providers
  private static final String BOUNCYCASTLE_PROVIDER =
      "org.bouncycastle.jce.provider.BouncyCastleProvider";

  public static void load() throws Exception {
    loadNonFips();
    // AmazonCorrettoCryptoProvider.install();
    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");

    if (AmazonCorrettoCryptoProvider.INSTANCE.getLoadingError() != null) {
      throw new AssertionError(AmazonCorrettoCryptoProvider.INSTANCE.getLoadingError());
    }

    assertEquals(AmazonCorrettoCryptoProvider.class, c.getProvider().getClass());
  }

  private static void loadNonFips() throws ReflectiveOperationException {
    System.setProperty(
        "org.bouncycastle.drbg.entropysource", FastEntropySourceProvider.class.getName());

    if (!installProviderAtHighestPriority((Provider) construct(BOUNCYCASTLE_PROVIDER))) {
      throw new AssertionError("Unable to install the BouncyCastleProvider.");
    }

    if (!installProviderAtHighestPriority(AmazonCorrettoCryptoProvider.INSTANCE)) {
      throw new RuntimeException("Failed to install ACCP");
    }
  }

  /** Returns the result of calling the default constructor for {@code className}. */
  private static Object construct(final String className) throws ReflectiveOperationException {
    return Class.forName(className).getDeclaredConstructor().newInstance();
  }

  /**
   * Installs {@code prov} at the highest priority in the JCE/JCA.
   *
   * @param prov
   * @return true if and only if {@code prov} is now at the highest priority
   */
  static boolean installProviderAtHighestPriority(final Provider prov) {
    // Remove the provider if present
    Security.removeProvider(prov.getName());
    return Security.insertProviderAt(prov, 1) == 1;
  }

  /** Provides non-blocking entropy to BouncyCastle (non-FIPS mode). */
  public static final class FastEntropySourceProvider extends BasicEntropySourceProvider {
    private static final List<String> PREFERRED_SOURCES =
        Arrays.asList("LibCryptoRng", "NativePRNGNonBlocking", "Windows-PRNG");

    public FastEntropySourceProvider() throws NoSuchAlgorithmException {
      super(selectSecureRandom(), true);
    }

    private static SecureRandom selectSecureRandom() throws NoSuchAlgorithmException {
      for (final String algorithm : PREFERRED_SOURCES) {
        try {
          final SecureRandom rng = SecureRandom.getInstance(algorithm);
          return rng;
        } catch (final NoSuchAlgorithmException ex) {
          // Expected
        }
      }
      throw new AssertionError("No acceptable EntropySource found.");
    }
  }
}
