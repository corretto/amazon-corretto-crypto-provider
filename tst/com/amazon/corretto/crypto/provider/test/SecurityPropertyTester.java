// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import static org.junit.Assert.assertEquals;

import java.security.Provider;
import java.security.Security;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;

/**
 * This is a special stand-alone test case which asserts that AmazonCorrettoCryptoProvider is installed as the highers priority provider and is functional.
 */
public class SecurityPropertyTester {
  public static void main(String[] args) {
    final Provider provider = Security.getProviders()[0];
    assertEquals("AmazonCorrettoCryptoProvider", provider.getName());
    final AmazonCorrettoCryptoProvider njb = (AmazonCorrettoCryptoProvider) provider;
    njb.assertHealthy();
  }
}
