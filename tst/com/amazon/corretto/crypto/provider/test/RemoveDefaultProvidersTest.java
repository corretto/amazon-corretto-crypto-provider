// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.NATIVE_PROVIDER;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

@Execution(ExecutionMode.SAME_THREAD)
@ExtendWith(TestResultLogger.class)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ_WRITE)
// This test is used to prove that functionality tested within it is independent of
// default-registered JDK providers (SunEC, SunJCE, etc.). We take a global resource
// lock because other tests rely on default providers and JCA state is global.
public class RemoveDefaultProvidersTest {
  private static List<Provider> defaultProviders;

  @BeforeAll
  static void removeAndStoreProviders() {
    defaultProviders = new ArrayList<>();
    for (Provider provider : Security.getProviders()) {
      defaultProviders.add(provider);
      Security.removeProvider(provider.getName());
    }
    assertTrue(Security.getProviders().length == 0);
  }

  @AfterAll
  static void restoreProviders() {
    assertTrue(Security.getProviders().length == 0);
    for (Provider provider : defaultProviders) {
      Security.addProvider(provider);
    }
  }

  @Test
  void testEdDSASignature() throws Exception {
    final byte[] message = new byte[] {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    final KeyPair keyPair =
        KeyPairGenerator.getInstance("EdDSA", NATIVE_PROVIDER).generateKeyPair();
    final Signature signature = Signature.getInstance("EdDSA", NATIVE_PROVIDER);
    signature.initSign(keyPair.getPrivate());
    signature.update(message);
    final byte[] signatureBytes = signature.sign();
    signature.initVerify(keyPair.getPublic());
    signature.update(message);
    assertTrue(signature.verify(signatureBytes));
  }
}
