// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.benchmarks;

import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.openssl.jostle.jcajce.provider.JostleProvider;

class BenchmarkUtils {
  private BenchmarkUtils() {}

  /** Name OpenSSL Jostle registers itself under. */
  static final String JOSTLE_PROVIDER_NAME = "JSL";

  private static final SecureRandom sr = new SecureRandom();
  private static final List<Provider> DEFAULT_PROVIDERS = new ArrayList<>();
  private static AmazonCorrettoCryptoProvider accp = null;
  private static BouncyCastleProvider bc = null;
  private static JostleProvider jostle = null;

  static {
    // For BC, Jostle and ACCP, if they are installed statically, we just remove them.
    for (Provider provider : Security.getProviders()) {
      if ("AmazonCorrettoCryptoProvider".equals(provider.getName())) {
        accp = (AmazonCorrettoCryptoProvider) provider;
      } else if ("BC".equals(provider.getName())) {
        bc = (BouncyCastleProvider) provider;
      } else if (JOSTLE_PROVIDER_NAME.equals(provider.getName())) {
        jostle = (JostleProvider) provider;
      } else {
        DEFAULT_PROVIDERS.add(provider);
      }
    }
    if (accp == null) {
      accp = AmazonCorrettoCryptoProvider.INSTANCE;
    }
    if (bc == null) {
      bc = new BouncyCastleProvider();
    }
    removeAllProviders();
    installDefaultProviders();
  }

  /**
   * Constructing a JostleProvider extracts and loads OpenSSL, so forks that never benchmark it
   * should not pay for it.
   */
  private static synchronized JostleProvider jostle() {
    if (jostle == null) {
      jostle = new JostleProvider();
    }
    return jostle;
  }

  static byte[] getRandBytes(int n) {
    byte[] ret = new byte[n];
    final int bcMaxSize = 32768;
    for (int ii = 0; ii < n; ii += bcMaxSize) {
      byte[] data = new byte[bcMaxSize];
      sr.nextBytes(data);
      System.arraycopy(data, 0, ret, ii, Math.min(bcMaxSize, n - ii));
    }
    return ret;
  }

  static void setupProvider(String providerName) {
    removeAllProviders();
    switch (providerName) {
      case "AmazonCorrettoCryptoProvider":
        installDefaultProviders();
        Security.insertProviderAt(accp, 1);
        accp.assertHealthy();
        break;
      case "BC":
        Security.insertProviderAt(bc, 1);
        break;
      case JOSTLE_PROVIDER_NAME:
        // Jostle registers no "SHA" alias, which SUN's NativePRNG needs to seed its mixer, so the
        // JDK providers have to stay available underneath it.
        installDefaultProviders();
        Security.insertProviderAt(jostle(), 1);
        break;
      case "SUN":
      case "SunEC":
      case "SunJCE":
      case "SunRsaSign":
        installDefaultProviders();
        break;
      default:
        throw new RuntimeException("Unrecognized provider: " + providerName);
    }
  }

  static void installDefaultProviders() {
    for (Provider provider : DEFAULT_PROVIDERS) {
      Security.addProvider(provider);
    }
  }

  static void removeAllProviders() {
    for (Provider provider : Security.getProviders()) {
      Security.removeProvider(provider.getName());
    }
  }

  static int getJavaVersion() {
    final String strVersion = System.getProperty("java.specification.version");
    final String[] parts = strVersion.split("\\.");
    if (parts[0].equals("1")) {
      return Integer.parseInt(parts[1]);
    }
    return Integer.parseInt(parts[0]);
  }
}
