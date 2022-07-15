// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.NATIVE_PROVIDER;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.HashSet;
import java.util.Set;

import javax.net.ssl.SSLContext;

/**
 * This is a special stand-alone test case which asserts that AmazonCorrettoCryptoProvider is installed
 * as the highest priority provider and is functional.
 */
public final class SecurityPropertyTester {
  public static void main(String[] args) throws Exception {
    NATIVE_PROVIDER.assertHealthy();
    final boolean fipsMode = Boolean.getBoolean("FIPS");
    System.out.println("FIPS? " + NATIVE_PROVIDER.isFips());
    assertEquals(fipsMode, NATIVE_PROVIDER.isFips());

    final Provider provider = Security.getProviders()[0];
    assertEquals(NATIVE_PROVIDER.getName(), provider.getName());

    // Ensure that TLS works as expected
    SSLContext.getInstance("TLS"); // Throws exception on problem

    // We know that Java has the SunEC provider which can generate EC keys.
    // We try to grab it to show that the nothing interfered with proper provider loading.
    @SuppressWarnings("unused")
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "SunEC");

    // Ensure we properly configured ourselves as "strong" instance of SecureRandom
    // Applications should never use getInstanceStrong as it is an anti-pattern.
    final SecureRandom strongRng = SecureRandom.getInstanceStrong();
    assertEquals(NATIVE_PROVIDER.getName(), strongRng.getProvider().getName());

    // Also ensure that nothing shows up twice
    Set<String> names = new HashSet<>();
    for (Provider p : Security.getProviders()) {
        if (!names.add(p.getName())) {
            throw new AssertionError("Duplicate found for " + p.getName());
        }
    }
  }

  private SecurityPropertyTester() {
    // Prevent instantiation
  }
}
