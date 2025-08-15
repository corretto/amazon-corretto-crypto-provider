// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class KeyPairGeneratorTest {

  KeyPairGenerator getXECKeyPairGenerator() {
    try {
      return KeyPairGenerator.getInstance("X25519", TestUtil.NATIVE_PROVIDER);
    } catch (final NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  @Test
  public void generateXECKeys() {
    final KeyPairGenerator keyPairGenerator = getXECKeyPairGenerator();
    assertEquals("X25519", keyPairGenerator.getAlgorithm());

    final KeyPair keyPair = keyPairGenerator.generateKeyPair();
    assertNotNull(keyPair);

    final PrivateKey privateKey = keyPair.getPrivate();
    assertNotNull(privateKey);
    assertEquals("PKCS#8", privateKey.getFormat());
    assertEquals("XDH", privateKey.getAlgorithm());
    assertEquals(48, privateKey.getEncoded().length);

    final PublicKey publicKey = keyPair.getPublic();
    assertNotNull(publicKey);
    assertEquals("X.509", publicKey.getFormat());
    assertEquals("XDH", publicKey.getAlgorithm());
    assertEquals(44, publicKey.getEncoded().length);
  }
}
