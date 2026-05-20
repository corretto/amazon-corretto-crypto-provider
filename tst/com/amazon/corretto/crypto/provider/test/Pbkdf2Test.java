// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.decodeHex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.spec.InvalidKeySpecException;
import java.util.stream.Stream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class Pbkdf2Test {

  private static final String[] DIGESTS = {
    "HmacSHA1", "HmacSHA224", "HmacSHA256", "HmacSHA384", "HmacSHA512"
  };

  // Args: id, digest, password, salt, iterations, dkLenBytes, expectedHex
  // EmptyPassword, RFC6070Vectors kKey1-4, SHA2 kKey1, SHA2 kKey2 vectors are from
  // https://github.com/aws/aws-lc/blob/main/crypto/fipsmodule/pbkdf/pbkdf_test.cc
  // SHA-224 and SHA-384 vectors are from
  // https://github.com/Anti-weakpasswords/PBKDF2-GCC-OpenSSL-library/blob/master/pbkdf2_test.sh
  private static Stream<Arguments> katVectors() {
    return Stream.of(
        Arguments.of(
            "EmptyPassword",
            "HmacSHA1",
            "",
            "salt",
            1,
            20,
            "a33dddc30478185515311f8752895d36ea4363a2"),
        Arguments.of(
            "RFC6070Vectors kKey1",
            "HmacSHA1",
            "password",
            "salt",
            1,
            20,
            "0c60c80f961f0e71f3a9b524af6012062fe037a6"),
        Arguments.of(
            "RFC6070Vectors kKey2",
            "HmacSHA1",
            "password",
            "salt",
            2,
            20,
            "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"),
        Arguments.of(
            "RFC6070Vectors kKey3",
            "HmacSHA1",
            "pass\0word",
            "sa\0lt",
            4096,
            16,
            "56fa6aa75548099dcc37d7f03425e0c3"),
        Arguments.of(
            "RFC6070Vectors kKey4",
            "HmacSHA1",
            "passwordPASSWORDpassword",
            "saltSALTsaltSALTsaltSALTsaltSALTsalt",
            4096,
            25,
            "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"),
        Arguments.of(
            "SHA-224 c=1",
            "HmacSHA224",
            "passDATAb00AB7YxDTTlRH2dqxD",
            "saltKEYbcTcXHCBxtjD2PnBh44A",
            1,
            28,
            "86ab2f3d0cb39839b46da2dd8f210915d79ad2e6f2093d155d75c8d9"),
        Arguments.of(
            "SHA-224 c=100000",
            "HmacSHA224",
            "passDATAb00AB7YxDTTlRH2dqxD",
            "saltKEYbcTcXHCBxtjD2PnBh44A",
            100000,
            28,
            "0adf2d99e7ff8dbc6b1df4382d32959021bfdacb99b796bf9089d0e3"),
        Arguments.of(
            "SHA2 kKey1",
            "HmacSHA256",
            "password",
            "salt",
            2,
            32,
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"),
        Arguments.of(
            "SHA-384 c=1",
            "HmacSHA384",
            "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqK",
            "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcG",
            1,
            48,
            "0644a3489b088ad85a0e42be3e7f82500ec18936699151a2c90497151bac7bb6"
                + "9300386a5e798795be3cef0a3c803227"),
        Arguments.of(
            "SHA-384 c=100000",
            "HmacSHA384",
            "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqK",
            "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcG",
            100000,
            48,
            "bf625685b48fe6f187a1780c5cb8e1e4a7b0dbd6f551827f7b2b598735eac158"
                + "d77afd3602383d9a685d87f8b089af30"),
        Arguments.of(
            "SHA2 kKey2",
            "HmacSHA512",
            "passwordPASSWORDpassword",
            "saltSALTsaltSALTsaltSALTsaltSALTsalt",
            4096,
            64,
            "8c0511f4c6e597c6ac6315d8f0362e225f3c501495ba23b868c005174dc4ee71"
                + "115b59f9e60cd9532fa33e0f75aefe30225c583a186cd82bd4daea9724a3d3b8"));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("katVectors")
  public void checkKat(
      String id,
      String digest,
      String password,
      String salt,
      int iterations,
      int dkLenBytes,
      String expectedHex)
      throws Exception {

    final SecretKeyFactory skf =
        SecretKeyFactory.getInstance("PBKDF2With" + digest, TestUtil.NATIVE_PROVIDER);
    final PBEKeySpec spec =
        new PBEKeySpec(password.toCharArray(), salt.getBytes(), iterations, dkLenBytes * 8);
    final byte[] expected = decodeHex(expectedHex);
    final byte[] actual = skf.generateSecret(spec).getEncoded();
    assertArrayEquals(expected, actual);
  }

  @Test
  public void testInteroperability() throws Exception {
    final int[] iterations = {1, 2, 100, 4096};
    final int[] keyLenBytes = {16, 32, 64};

    for (String digest : DIGESTS) {
      final SecretKeyFactory sun = SecretKeyFactory.getInstance("PBKDF2With" + digest, "SunJCE");
      final SecretKeyFactory bc =
          SecretKeyFactory.getInstance("PBKDF2With" + digest, TestUtil.BC_PROVIDER);
      final SecretKeyFactory accp =
          SecretKeyFactory.getInstance("PBKDF2With" + digest, TestUtil.NATIVE_PROVIDER);

      for (int iter : iterations) {
        for (int len : keyLenBytes) {
          final PBEKeySpec spec =
              new PBEKeySpec("password".toCharArray(), "salt".getBytes(), iter, len * 8);
          final SecretKey sunKey = sun.generateSecret(spec);
          final SecretKey bcKey = bc.generateSecret(spec);
          final SecretKey accpKey = accp.generateSecret(spec);
          final String label = digest + " iter=" + iter + " len=" + len;

          assertArrayEquals(sunKey.getEncoded(), accpKey.getEncoded(), "SunJCE keys- " + label);
          assertArrayEquals(bcKey.getEncoded(), accpKey.getEncoded(), "BC keys - " + label);

          // SunJCE registers the keys in full form, i.e "PBKDF2WithHmacSHA256", while BC registers
          // all digests under "PBKDF"
          assertEquals(sunKey.getAlgorithm(), accpKey.getAlgorithm(), label);
        }
      }
    }
  }

  @Test
  public void testUtf8Encoding() throws Exception {
    final char[][] passwords = {"fooä".toCharArray(), "bár".toCharArray()};
    final SecretKeyFactory sun = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", "SunJCE");
    final SecretKeyFactory accp =
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", TestUtil.NATIVE_PROVIDER);
    for (char[] password : passwords) {
      final PBEKeySpec spec = new PBEKeySpec(password, "salt".getBytes(), 1000, 256);
      assertArrayEquals(
          sun.generateSecret(spec).getEncoded(),
          accp.generateSecret(spec).getEncoded(),
          new String(password));
    }
  }

  // Verify wrong spec type, null salt, and zero key length each throw InvalidKeySpecException
  @Test
  public void invalidParameterTests() throws Exception {
    final SecretKeyFactory skf =
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", TestUtil.NATIVE_PROVIDER);
    assertThrows(
        InvalidKeySpecException.class,
        () -> skf.generateSecret(new SecretKeySpec(new byte[16], "PBKDF2")));
    assertThrows(
        InvalidKeySpecException.class,
        () -> skf.generateSecret(new PBEKeySpec("password".toCharArray())));
    assertThrows(
        InvalidKeySpecException.class,
        () -> skf.generateSecret(new PBEKeySpec("password".toCharArray(), "salt".getBytes(), 1)));
  }

  @Test
  public void pbkdf2sAreAvailable() throws Exception {
    for (String digest : DIGESTS) {
      SecretKeyFactory.getInstance("PBKDF2With" + digest, TestUtil.NATIVE_PROVIDER);
    }
  }
}
