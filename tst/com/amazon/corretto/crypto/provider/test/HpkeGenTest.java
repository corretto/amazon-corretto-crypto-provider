// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.amazon.corretto.crypto.provider.HpkeParameterSpec;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class HpkeGenTest {
  static List<HpkeParameterSpec> namedSpecs() {
    return Arrays.asList(
        HpkeParameterSpec.X25519Sha256Aes128gcm,
        HpkeParameterSpec.X25519Sha256Chapoly,
        HpkeParameterSpec.Mlkem768Sha256Aes256gcm,
        HpkeParameterSpec.Mlkem1024Sha384Aes256gcm,
        HpkeParameterSpec.Pqt25519Sha256Aes256gcm,
        HpkeParameterSpec.Pqt256Sha256Aes256gcm,
        HpkeParameterSpec.Pqt384Sha384Aes256gcm);
  }

  private KeyPairGenerator getGenerator() throws GeneralSecurityException {
    return KeyPairGenerator.getInstance("HPKE", TestUtil.NATIVE_PROVIDER);
  }

  @ParameterizedTest
  @MethodSource("namedSpecs")
  public void basicKeygen(HpkeParameterSpec spec) throws GeneralSecurityException {
    final KeyPairGenerator generator = getGenerator();
    generator.initialize(spec);
    final KeyPair keyPair = generator.generateKeyPair();
    assertNotNull(keyPair.getPublic());
    assertNotNull(keyPair.getPrivate());
  }
}
