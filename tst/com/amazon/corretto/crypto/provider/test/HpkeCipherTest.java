// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import com.amazon.corretto.crypto.provider.HpkeParameterSpec;
import java.security.*;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class HpkeCipherTest {
  private KeyPairGenerator getGenerator() throws GeneralSecurityException {
    return KeyPairGenerator.getInstance("HPKE", TestUtil.NATIVE_PROVIDER);
  }

  private static Cipher getCipher() throws GeneralSecurityException {
    return Cipher.getInstance("HPKE", TestUtil.NATIVE_PROVIDER);
  }

  @Test
  public void testWrapUnwrap() throws GeneralSecurityException {
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
      final Cipher wrapCipher = getCipher();
      final Cipher unwrapCipher = getCipher();

      // Generate a key pair
      generator.initialize(spec);
      final KeyPair keyPair = generator.generateKeyPair();
      assertNotNull(keyPair.getPublic());
      assertNotNull(keyPair.getPrivate());

      // Initialize ciphers
      wrapCipher.init(Cipher.WRAP_MODE, keyPair.getPublic());
      unwrapCipher.init(Cipher.UNWRAP_MODE, keyPair.getPrivate());

      // Test wrapping AES key
      final SecretKeySpec aesKey = new SecretKeySpec(TestUtil.getRandomBytes(16), "AES");
      final SecretKey unwrappedSecretKey =
          (SecretKey) unwrapCipher.unwrap(wrapCipher.wrap(aesKey), "AES", Cipher.SECRET_KEY);
      assertEquals(aesKey.getAlgorithm(), unwrappedSecretKey.getAlgorithm());
      assertArrayEquals(aesKey.getEncoded(), unwrappedSecretKey.getEncoded());

      // Test wrapping RSA keys
      final KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA");
      rsaGenerator.initialize(4096);
      final KeyPair rsaKeyPair = rsaGenerator.generateKeyPair();
      final PublicKey rsaPublicKey = rsaKeyPair.getPublic();
      final PublicKey unwrappedRsaPublicKey =
          (PublicKey) unwrapCipher.unwrap(wrapCipher.wrap(rsaPublicKey), "RSA", Cipher.PUBLIC_KEY);
      assertEquals(rsaPublicKey.getAlgorithm(), unwrappedRsaPublicKey.getAlgorithm());
      assertArrayEquals(rsaPublicKey.getEncoded(), unwrappedRsaPublicKey.getEncoded());
      final PrivateKey rsaPrivateKey = rsaKeyPair.getPrivate();
      final PrivateKey unwrappedRsaPrivateKey =
          (PrivateKey)
              unwrapCipher.unwrap(wrapCipher.wrap(rsaPrivateKey), "RSA", Cipher.PRIVATE_KEY);
      assertEquals(rsaPrivateKey.getAlgorithm(), unwrappedRsaPrivateKey.getAlgorithm());
      assertArrayEquals(rsaPrivateKey.getEncoded(), unwrappedRsaPrivateKey.getEncoded());

      // Test wrapping EC keys
      final KeyPairGenerator ecGenerator = KeyPairGenerator.getInstance("EC");
      ecGenerator.initialize(new ECGenParameterSpec("NIST P-384"));
      final KeyPair ecKeyPair = ecGenerator.generateKeyPair();
      final PublicKey ecPublicKey = ecKeyPair.getPublic();
      final PublicKey unwrappedEcPublicKey =
          (PublicKey) unwrapCipher.unwrap(wrapCipher.wrap(ecPublicKey), "EC", Cipher.PUBLIC_KEY);
      assertEquals(ecPublicKey.getAlgorithm(), unwrappedEcPublicKey.getAlgorithm());
      assertArrayEquals(ecPublicKey.getEncoded(), unwrappedEcPublicKey.getEncoded());
      final PrivateKey ecPrivateKey = ecKeyPair.getPrivate();
      final PrivateKey unwrappedEcPrivateKey =
          (PrivateKey) unwrapCipher.unwrap(wrapCipher.wrap(ecPrivateKey), "EC", Cipher.PRIVATE_KEY);
      assertEquals(ecPrivateKey.getAlgorithm(), unwrappedEcPrivateKey.getAlgorithm());
      assertArrayEquals(ecPrivateKey.getEncoded(), unwrappedEcPrivateKey.getEncoded());
    }
  }
}
