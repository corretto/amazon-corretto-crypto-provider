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

  private KeyPair getKeyPair(HpkeParameterSpec spec) throws GeneralSecurityException {
    final KeyPairGenerator generator = getGenerator();
    generator.initialize(spec);
    return generator.generateKeyPair();
  }

  private static Cipher getCipher() throws GeneralSecurityException {
    return Cipher.getInstance("HPKE", TestUtil.NATIVE_PROVIDER);
  }

  private static Cipher getInitCipher(KeyPair keyPair, int opmode) throws GeneralSecurityException {
    Cipher cipher = getCipher();
    if ((opmode == Cipher.ENCRYPT_MODE) || (opmode == Cipher.WRAP_MODE)) {
      cipher.init(opmode, keyPair.getPublic());
    } else if ((opmode == Cipher.DECRYPT_MODE) || (opmode == Cipher.UNWRAP_MODE)) {
      cipher.init(opmode, keyPair.getPrivate());
    }
    return cipher;
  }

  @Test
  public void basicCorrectness() throws GeneralSecurityException {
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

      // Generate a key pair
      final KeyPair keyPair = getKeyPair(spec);
      assertNotNull(keyPair.getPublic());
      assertNotNull(keyPair.getPrivate());

      // Initialize ciphers
      final Cipher encryptCipher = getInitCipher(keyPair, Cipher.ENCRYPT_MODE);
      final Cipher decryptCipher = getInitCipher(keyPair, Cipher.DECRYPT_MODE);
      final Cipher wrapCipher = getInitCipher(keyPair, Cipher.WRAP_MODE);
      final Cipher unwrapCipher = getInitCipher(keyPair, Cipher.UNWRAP_MODE);

      // Test encrypting data with aad
      final byte[] message = TestUtil.arrayOf((byte) 0x42, 42);
      final byte[] aad1 = TestUtil.arrayOf((byte) 0x24, 24);
      final byte[] aad2 = TestUtil.arrayOf((byte) 0x12, 12);
      encryptCipher.updateAAD(aad1, 0, aad1.length);
      encryptCipher.updateAAD(aad2, 0, aad2.length);
      final byte[] ciphertext = encryptCipher.doFinal(message);
      decryptCipher.updateAAD(aad1, 0, aad1.length);
      decryptCipher.updateAAD(aad2, 0, aad2.length);
      final byte[] decrypted = decryptCipher.doFinal(ciphertext);
      assertArrayEquals(message, decrypted);

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

  @Test
  public void invalidUses() throws GeneralSecurityException {
    final HpkeParameterSpec spec = HpkeParameterSpec.Mlkem768Sha256Chapoly;
    final KeyPair keyPair = getKeyPair(spec);
    final byte[] input = TestUtil.arrayOf((byte) 0x42, 42);

    final Cipher wrapCipher = getInitCipher(keyPair, Cipher.WRAP_MODE);
    final Cipher unwrapCipher = getInitCipher(keyPair, Cipher.UNWRAP_MODE);
    TestUtil.assertThrows(IllegalStateException.class, () -> wrapCipher.doFinal(input));
    TestUtil.assertThrows(IllegalStateException.class, () -> unwrapCipher.doFinal(input));

    final SecretKeySpec aesKey = new SecretKeySpec(TestUtil.getRandomBytes(16), "AES");
    final Cipher encryptCipher = getInitCipher(keyPair, Cipher.ENCRYPT_MODE);
    final Cipher decryptCipher = getInitCipher(keyPair, Cipher.DECRYPT_MODE);
    TestUtil.assertThrows(IllegalStateException.class, () -> encryptCipher.wrap(aesKey));
    TestUtil.assertThrows(
        IllegalStateException.class, () -> decryptCipher.unwrap(input, "AES", Cipher.SECRET_KEY));
  }
}
