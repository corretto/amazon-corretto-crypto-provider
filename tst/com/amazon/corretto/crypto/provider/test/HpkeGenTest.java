// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static org.junit.Assert.assertNotNull;

import com.amazon.corretto.crypto.provider.EvpHpkePrivateKey;
import com.amazon.corretto.crypto.provider.EvpHpkePublicKey;
import com.amazon.corretto.crypto.provider.HpkeParameterSpec;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class HpkeGenTest {
  private KeyPairGenerator getGenerator() throws GeneralSecurityException {
    return KeyPairGenerator.getInstance("HPKE", TestUtil.NATIVE_PROVIDER);
  }

  @Test
  public void testNamedSpecs() throws GeneralSecurityException {
    final HpkeParameterSpec[] namedSpecs = {
      HpkeParameterSpec.X25519Sha256Aes128gcm,
      HpkeParameterSpec.X25519Sha256Chapoly,
      HpkeParameterSpec.Mlkem768Sha256Aes128gcm,
      HpkeParameterSpec.Mlkem768Sha256Chapoly,
      HpkeParameterSpec.Mlkem1024Sha384Aes256gcm,
      HpkeParameterSpec.Pqt25519Sha256Aes128gcm,
      HpkeParameterSpec.Pqt25519768Sha256Chapoly,
      HpkeParameterSpec.Pqt256Sha256Aes128gcm,
      HpkeParameterSpec.Pqt384Sha384Aes256gcm
    };
    for (final HpkeParameterSpec spec : namedSpecs) {
      final KeyPairGenerator generator = getGenerator();
      generator.initialize(spec);
      final KeyPair keyPair = generator.generateKeyPair();
      final EvpHpkePublicKey pubKey = (EvpHpkePublicKey) keyPair.getPublic();
      final EvpHpkePrivateKey privKey = (EvpHpkePrivateKey) keyPair.getPrivate();

      assertNotNull(pubKey);
      assertNotNull(privKey);
      // TODO: do more checks
    }
  }
}
