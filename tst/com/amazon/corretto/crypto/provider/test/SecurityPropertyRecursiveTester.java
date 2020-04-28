// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;

import java.security.Provider;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * This is a special stand-alone test case which asserts that NativeJCEBindings is installed as the highers priority provider
 * and is functional even when NativeJCEBindings.install() is called prior to pulling providers from the internal list.
 * There was a bug previously with circular dependencies between Loader and the provider which manifested itself with
 * this failure.
 */
public class SecurityPropertyRecursiveTester {
  public static void main(String[] args) {
    AmazonCorrettoCryptoProvider.install();
    final Provider provider = Security.getProviders()[0];
    assertEquals("AmazonCorrettoCryptoProvider", provider.getName());
    final AmazonCorrettoCryptoProvider njb = (AmazonCorrettoCryptoProvider) provider;
    njb.assertHealthy();
    AmazonCorrettoCryptoProvider.INSTANCE.assertHealthy();
  }
}
