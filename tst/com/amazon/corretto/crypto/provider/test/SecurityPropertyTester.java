// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import static org.junit.Assert.assertEquals;

import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.util.HashSet;
import java.util.Set;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;

/**
 * This is a special stand-alone test case which asserts that AmazonCorrettoCryptoProvider is installed as the highers priority provider and is functional.
 */
public class SecurityPropertyTester {
  public static void main(String[] args) throws Exception {
    final Provider provider = Security.getProviders()[0];
    assertEquals("AmazonCorrettoCryptoProvider", provider.getName());
    final AmazonCorrettoCryptoProvider njb = (AmazonCorrettoCryptoProvider) provider;
    njb.assertHealthy();

    // We know that Java has the SunEC provider which can generate EC keys.
    // We try to grab it to show that the nothing interfered with proper provider loading.
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "SunEC");

    // Also ensure that nothing shows up twice
    Set<String> names = new HashSet<>();
    for (Provider p : Security.getProviders()) {
        if (!names.add(p.getName())) {
            throw new AssertionError("Duplicate found for " + p.getName());
        }
    }
  }
}
