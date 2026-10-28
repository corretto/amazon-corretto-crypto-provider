// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import com.amazon.corretto.crypto.provider.RuntimeCryptoException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Loads a release jar as a JCA provider and checks that it is healthy and is the build we expect.
 * Kept to Java 8 syntax so the same source runs on every supported JDK.
 *
 * <p>Usage: java -cp AmazonCorrettoCryptoProvider.jar:. ReleaseSmokeTest VERSION IS_FIPS
 */
public class ReleaseSmokeTest {
  private static final String PROVIDER_NAME = "AmazonCorrettoCryptoProvider";

  public static void main(String[] args) throws Exception {
    if (args.length != 2) {
      throw new IllegalArgumentException("usage: ReleaseSmokeTest VERSION IS_FIPS");
    }
    String expectedVersion = args[0];
    boolean expectedFips = Boolean.parseBoolean(args[1]);

    AmazonCorrettoCryptoProvider.install();
    AmazonCorrettoCryptoProvider accp = AmazonCorrettoCryptoProvider.INSTANCE;
    try {
      accp.assertHealthy();
    } catch (RuntimeCryptoException e) {
      System.err.println("ACCP health check failed: " + e.getMessage());
      throw e;
    }

    check(PROVIDER_NAME.equals(Security.getProviders()[0].getName()), "ACCP is not provider #1");
    check(
        expectedVersion.equals(accp.getVersionStr()),
        "version " + accp.getVersionStr() + " != " + expectedVersion);
    check(accp.isFips() == expectedFips, "isFips() " + accp.isFips() + " != " + expectedFips);

    MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
    check(PROVIDER_NAME.equals(sha256.getProvider().getName()), "SHA-256 not served by ACCP");
    // FIPS 180-2 Appendix B.1 known answer.
    check(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            .equals(hex(sha256.digest("abc".getBytes(StandardCharsets.US_ASCII)))),
        "SHA-256 known answer mismatch");

    Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
    check(PROVIDER_NAME.equals(gcm.getProvider().getName()), "AES-GCM not served by ACCP");
    SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
    GCMParameterSpec iv = new GCMParameterSpec(128, new byte[12]);
    byte[] plaintext = "release smoke test".getBytes(StandardCharsets.US_ASCII);
    gcm.init(Cipher.ENCRYPT_MODE, key, iv);
    byte[] ciphertext = gcm.doFinal(plaintext);
    gcm.init(Cipher.DECRYPT_MODE, key, iv);
    check(
        new String(gcm.doFinal(ciphertext), StandardCharsets.US_ASCII).equals("release smoke test"),
        "AES-GCM round trip mismatch");

    System.out.println(
        "OK: "
            + accp
            + " fips="
            + accp.isFips()
            + " aws-lc="
            + accp.getAwsLcVersionStr()
            + " java="
            + System.getProperty("java.version"));
  }

  private static void check(boolean condition, String message) {
    if (!condition) {
      throw new AssertionError(message);
    }
  }

  private static String hex(byte[] bytes) {
    StringBuilder sb = new StringBuilder();
    for (byte b : bytes) {
      sb.append(String.format("%02x", b));
    }
    return sb.toString();
  }
}
