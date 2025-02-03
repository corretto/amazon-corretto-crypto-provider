// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.stream.Stream;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.util.Arrays;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class AesXtsTest {

  static Cipher getAesXtsCipher() {
    try {
      return Cipher.getInstance("AES/XTS/NoPadding", TestUtil.NATIVE_PROVIDER);
    } catch (final NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    } catch (NoSuchPaddingException e) {
      throw new RuntimeException(e);
    }
  }

  private static class AesXtsTestCase {
    public String keyHex;
    public String tweakHex;
    public String inputHex;
    public String cipherTextHex;

    AesXtsTestCase() {
      keyHex = "";
      tweakHex = "";
      inputHex = "";
      cipherTextHex = "";
    }

    AesXtsTestCase addKey(final String data) {
      keyHex += data;
      return this;
    }

    AesXtsTestCase addTweak(final String data) {
      tweakHex += data;
      return this;
    }

    AesXtsTestCase addInput(final String data) {
      inputHex += data;
      return this;
    }

    AesXtsTestCase addCipherText(final String data) {
      cipherTextHex += data;
      return this;
    }

    void checkPositive() {
      try {
        final SecretKeySpec key = new SecretKeySpec(TestUtil.decodeHex(keyHex), "AES-XTS");
        final byte[] input = TestUtil.decodeHex(inputHex);
        final IvParameterSpec tweak = new IvParameterSpec(TestUtil.decodeHex(tweakHex));

        final Cipher cipher = AesXtsTest.getAesXtsCipher();
        cipher.init(Cipher.ENCRYPT_MODE, key, tweak);
        final byte[] actualCipherText = cipher.doFinal(input);
        assertArrayEquals(TestUtil.decodeHex(cipherTextHex), actualCipherText);

        cipher.init(Cipher.DECRYPT_MODE, key, tweak);
        assertArrayEquals(input, cipher.doFinal(actualCipherText));
      } catch (final Exception e) {
        throw new RuntimeException(e);
      }
    }

    void checkNegative() {
      // The last byte of expected cipher text is expected to be tampered.
      try {
        final SecretKeySpec key = new SecretKeySpec(TestUtil.decodeHex(keyHex), "AES-XTS");
        final byte[] input = TestUtil.decodeHex(inputHex);
        final IvParameterSpec tweak = new IvParameterSpec(TestUtil.decodeHex(tweakHex));

        final Cipher cipher = AesXtsTest.getAesXtsCipher();
        cipher.init(Cipher.ENCRYPT_MODE, key, tweak);
        final byte[] actualCipherText = cipher.doFinal(input);
        final byte[] expectedCipherText = TestUtil.decodeHex(cipherTextHex);
        // The last byte of expected cipher text is expected to be tampered.
        assertNotEquals(lastElement(expectedCipherText), lastElement(actualCipherText));
      } catch (final Exception e) {
        throw new RuntimeException(e);
      }
    }

    private static byte lastElement(final byte[] data) {
      return data[data.length - 1];
    }
  }

  @Test
  public void xtsTestsFromAwsLCPositive() {
    final Stream<AesXtsTestCase> tests =
        Stream.of(
            new AesXtsTestCase()
                .addKey("2718281828459045235360287471352662497757247093699959574966967627314159")
                .addKey("2653589793238462643383279502884197169399375105820974944592")
                .addTweak("ff000000000000000000000000000000")
                .addInput("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122")
                .addInput("232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445")
                .addInput("464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768")
                .addInput("696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b")
                .addInput("8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadae")
                .addInput("afb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1")
                .addInput("d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4")
                .addInput("f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f1011121314151617")
                .addInput("18191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a")
                .addInput("3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d")
                .addInput("5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80")
                .addInput("8182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3")
                .addInput("a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6")
                .addInput("c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9")
                .addInput("eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
                .addCipherText(
                    "1c3b3a102f770386e4836c99e370cf9bea00803f5e482357a4ae12d414a3e63b5d31e2")
                .addCipherText(
                    "76f8fe4a8d66b317f9ac683f44680a86ac35adfc3345befecb4bb188fd5776926c49a3")
                .addCipherText(
                    "095eb108fd1098baec70aaa66999a72a82f27d848b21d4a741b0c5cd4d5fff9dac89ae")
                .addCipherText(
                    "ba122961d03a757123e9870f8acf1000020887891429ca2a3e7a7d7df7b10355165c8b")
                .addCipherText(
                    "9a6d0a7de8b062c4500dc4cd120c0f7418dae3d0b5781c34803fa75421c790dfe1de18")
                .addCipherText(
                    "34f280d7667b327f6c8cd7557e12ac3a0f93ec05c52e0493ef31a12d3d9260f79a289d")
                .addCipherText(
                    "6a379bc70c50841473d1a8cc81ec583e9645e07b8d9670655ba5bbcfecc6dc3966380a")
                .addCipherText(
                    "d8fecb17b6ba02469a020a84e18e8f84252070c13e9f1f289be54fbc481457778f6160")
                .addCipherText(
                    "15e1327a02b140f1505eb309326d68378f8374595c849d84f4c333ec4423885143cb47")
                .addCipherText(
                    "bd71c5edae9be69a2ffeceb1bec9de244fbe15992b11b77c040f12bd8f6a975a44a0f9")
                .addCipherText(
                    "0c29a9abc3d4d893927284c58754cce294529f8614dcd2aba991925fedc4ae74ffac6e")
                .addCipherText(
                    "333b93eb4aff0479da9a410e4450e0dd7ae4c6e2910900575da401fc07059f645e8b7e")
                .addCipherText(
                    "9bfdef33943054ff84011493c27b3429eaedb4ed5376441a77ed43851ad77f16f541df")
                .addCipherText(
                    "d269d50d6a5f14fb0aab1cbb4c1550be97f7ab4066193c4caa773dad38014bd2092fa7")
                .addCipherText("55c824bb5e54c4f36ffda9fcea70b9c6e693e148c151"),
            // https://github.com/BrianGladman/modes/blob/master/testvals/xts.6#L313
            // VEC 30, len = 16 bytes = 1 block
            new AesXtsTestCase()
                .addKey("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0")
                .addKey("bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0afaeadacabaaa9a8a7a6a5a4a3a2a1a0")
                .addTweak("9a785634120000000000000000000000")
                .addInput("000102030405060708090a0b0c0d0e0f")
                .addCipherText("c30ca8f2ed57307edc87e544867ac888"),
            // https://github.com/BrianGladman/modes/blob/master/testvals/xts.6#L321
            // VEC 31, len = 17 bytes = 1 block + 1 byte
            new AesXtsTestCase()
                .addKey("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0")
                .addKey("bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0afaeadacabaaa9a8a7a6a5a4a3a2a1a0")
                .addTweak("9a785634120000000000000000000000")
                .addInput("000102030405060708090a0b0c0d0e0f10")
                .addCipherText("7f117752cc598a8b0d81d88af9f9bec8c3"),
            // https://github.com/BrianGladman/modes/blob/master/testvals/xts.6#L361
            // VEC 36, len = 22 bytes = 1 block + 6 bytes
            new AesXtsTestCase()
                .addKey("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0")
                .addKey("bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0afaeadacabaaa9a8a7a6a5a4a3a2a1a0")
                .addTweak("9a785634120000000000000000000000")
                .addInput("000102030405060708090a0b0c0d0e0f101112131415")
                .addCipherText("75e8188bcce59ada939f57de2cb9a489c30ca8f2ed57"),
            // https://github.com/BrianGladman/modes/blob/master/testvals/xts.6#L433
            // VEC 45, len = 31 bytes = 1 block + 15 bytes
            new AesXtsTestCase()
                .addKey("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0")
                .addKey("bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0afaeadacabaaa9a8a7a6a5a4a3a2a1a0")
                .addTweak("9a785634120000000000000000000000")
                .addInput("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e")
                .addCipherText("581ea1fee5516ad432ddebe75fd27c6fc30ca8f2ed57307edc87e544867ac8"),
            // https://github.com/BrianGladman/modes/blob/master/testvals/xts.6#L433
            // VEC 45, len = 31 bytes = 1 block + 15 bytes
            new AesXtsTestCase()
                .addKey("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0")
                .addKey("bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0afaeadacabaaa9a8a7a6a5a4a3a2a1a0")
                .addTweak("9a785634120000000000000000000000")
                .addInput("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e")
                .addCipherText("581ea1fee5516ad432ddebe75fd27c6fc30ca8f2ed57307edc87e544867ac8"),
            // https://github.com/BrianGladman/modes/blob/master/testvals/xts.12#L2611
            // VEC 301, len = 32 bytes = 2 blocks (decryption vector)
            // This vector did not pass, the output below is the same for
            // the C implementation, |CRYPTO_xts128_encrypt|, and the AArch64 assembly
            new AesXtsTestCase()
                .addKey("1b278f1086f30d9f3b18a8dc2a258efea106b45bd18c760e360ba3c69859de47")
                .addKey("1c1c73d5f3de874486fa1d2c0573dfec5567d07468649a24dc9e72f421fa0b83")
                .addTweak("28000000000000000000000000000000")
                .addInput("208e5d0fa5ce130b294265e6430b98772eaae086a922391b98f0dec159a4f9c0")
                .addCipherText("7b8dc9d2c9bc031fa40ba63cce59428e09fccc48a96a95da120a592d2da9ff9c"),
            // https://github.com/BrianGladman/modes/blob/master/testvals/xts.12#L3411
            // VEC 401, len = 48 bytes = 3 blocks (decryption vector)
            new AesXtsTestCase()
                .addKey("1338d7d3d66137abf00c8f33050cff7e0a6fa10ff2e2bd860119dfa68ee815c4")
                .addKey("4aa1bfc76f2e084d81b862c05aae29711bf167fff7432a7b9c5899ab069fff0f")
                .addTweak("54000000000000000000000000000000")
                .addInput("922489de313fceb72a5ef2594d49eeb908afec966e89f0c7fbb4f6d37a559294")
                .addInput("2c53e3a65b37193d693467006595f811")
                .addCipherText("6f229c1b60833e2a50a041b360d99181a679f1361a011bf37b2e1565fda4a6b9")
                .addCipherText("22e5aabda21b167c030935e843d60c60"),
            // The following tests were generated by the C implementation to ensure
            // the AArch64 implementation produces the same output.
            // The plaintext lengths were chosen such that one or more vectors
            // exercise a certain path in the assembly code.
            // len = 44 bytes = 2 blocks + 12 bytes
            new AesXtsTestCase()
                .addKey("1338d7d3d66137abf00c8f33050cff7e0a6fa10ff2e2bd860119dfa68ee815c4")
                .addKey("4aa1bfc76f2e084d81b862c05aae29711bf167fff7432a7b9c5899ab069fff0f")
                .addTweak("54000000000000000000000000000000")
                .addInput("922489de313fceb72a5ef2594d49eeb908afec966e89f0c7fbb4f6d37a559294")
                .addInput("2c53e3a65b37193d69346700")
                .addCipherText("6f229c1b60833e2a50a041b360d991814c6ec7f3199d8b2482f5b19b64c32013")
                .addCipherText("a679f1361a011bf37b2e1565"),
            // Test vectors from NIST
            // https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
            // 256-bit key, 256-bit data (32 bytes, 2 blocks)
            new AesXtsTestCase()
                .addKey("1ea661c58d943a0e4801e42f4b0947149e7f9f8e3e68d0c7505210bd311a0e7c")
                .addKey("d6e13ffdf2418d8d1911c004cda58da3d619b7e2b9141e58318eea392cf41b08")
                .addTweak("adf8d92627464ad2f0428e84a9f87564")
                .addInput("2eedea52cd8215e1acc647e810bbc3642e87287f8d2e57e36c0a24fbc12a202e")
                .addCipherText("cbaad0e2f6cea3f50b37f934d46a9b130b9d54f07e34f36af793e86f73c6d7db"),
            // 256-bit key, 384-bit data (48 bytes, 3 blocks)
            new AesXtsTestCase()
                .addKey("266c336b3b01489f3267f52835fd92f674374b88b4e1ebd2d36a5f457581d9d0")
                .addKey("42c3eef7b0b7e5137b086496b4d9e6ac658d7196a23f23f036172fdb8faee527")
                .addTweak("06b209a7a22f486ecbfadb0f3137ba42")
                .addInput("ca7d65ef8d3dfad345b61ccddca1ad81de830b9e86c7b426d76cb7db766852d9")
                .addInput("81c6b21409399d78f42cc0b33a7bbb06")
                .addCipherText("c73256870cc2f4dd57acc74b5456dbd776912a128bc1f77d72cdebbf270044b7")
                .addCipherText("a43ceed29025e1e8be211fa3c3ed002d"),
            // 256-bit key, 384-bit data (48 bytes, 3 blocks)
            new AesXtsTestCase()
                .addKey("33e89e817ff8d037d6ac5a2296657503f20885d94c483e26449066bd9284d130")
                .addKey("2dbdbb4b66b6b9f4687f13dd028eb6aa528ca91deb9c5f40db93218806033801")
                .addTweak("a78c04335ab7498a52b81ed74b48e6cf")
                .addInput("14c3ac31291b075f40788247c3019e88c7b40bac3832da45bbc6c4fe7461371b")
                .addInput("4dfffb63f71c9f8edb98f28ff4f33121")
                .addCipherText("dead7e587519bc78c70d99279fbe3d9b1ad13cdaae69824e0ab8135413230bfd")
                .addCipherText("b13babe8f986fbb30d46ab5ec56b916e"));
    tests.forEach(AesXtsTestCase::checkPositive);
  }

  @Test
  public void xtsTestsFromAwsLCNegative() {
    final Stream<AesXtsTestCase> tests =
        Stream.of(
            new AesXtsTestCase()
                .addKey("2718281828459045235360287471352662497757247093699959574966967627314159")
                .addKey("2653589793238462643383279502884197169399375105820974944592")
                .addTweak("ff000000000000000000000000000000")
                .addInput("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122")
                .addInput("232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445")
                .addInput("464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768")
                .addInput("696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b")
                .addInput("8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadae")
                .addInput("afb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1")
                .addInput("d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4")
                .addInput("f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f1011121314151617")
                .addInput("18191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a")
                .addInput("3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d")
                .addInput("5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80")
                .addInput("8182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3")
                .addInput("a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6")
                .addInput("c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9")
                .addInput("eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
                .addCipherText(
                    "1c3b3a102f770386e4836c99e370cf9bea00803f5e482357a4ae12d414a3e63b5d31e2")
                .addCipherText(
                    "76f8fe4a8d66b317f9ac683f44680a86ac35adfc3345befecb4bb188fd5776926c49a3")
                .addCipherText(
                    "095eb108fd1098baec70aaa66999a72a82f27d848b21d4a741b0c5cd4d5fff9dac89ae")
                .addCipherText(
                    "ba122961d03a757123e9870f8acf1000020887891429ca2a3e7a7d7df7b10355165c8b")
                .addCipherText(
                    "9a6d0a7de8b062c4500dc4cd120c0f7418dae3d0b5781c34803fa75421c790dfe1de18")
                .addCipherText(
                    "34f280d7667b327f6c8cd7557e12ac3a0f93ec05c52e0493ef31a12d3d9260f79a289d")
                .addCipherText(
                    "6a379bc70c50841473d1a8cc81ec583e9645e07b8d9670655ba5bbcfecc6dc3966380a")
                .addCipherText(
                    "d8fecb17b6ba02469a020a84e18e8f84252070c13e9f1f289be54fbc481457778f6160")
                .addCipherText(
                    "15e1327a02b140f1505eb309326d68378f8374595c849d84f4c333ec4423885143cb47")
                .addCipherText(
                    "bd71c5edae9be69a2ffeceb1bec9de244fbe15992b11b77c040f12bd8f6a975a44a0f9")
                .addCipherText(
                    "0c29a9abc3d4d893927284c58754cce294529f8614dcd2aba991925fedc4ae74ffac6e")
                .addCipherText(
                    "333b93eb4aff0479da9a410e4450e0dd7ae4c6e2910900575da401fc07059f645e8b7e")
                .addCipherText(
                    "9bfdef33943054ff84011493c27b3429eaedb4ed5376441a77ed43851ad77f16f541df")
                .addCipherText(
                    "d269d50d6a5f14fb0aab1cbb4c1550be97f7ab4066193c4caa773dad38014bd2092fa7")
                .addCipherText("55c824bb5e54c4f36ffda9fcea70b9c6e693e148c100"),
            new AesXtsTestCase()
                .addKey("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0")
                .addKey("bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0afaeadacabaaa9a8a7a6a5a4a3a2a1a0")
                .addTweak("9a785634120000000000000000000000")
                .addInput("000102030405060708090a0b0c0d0e0f")
                .addCipherText("c30ca8f2ed57307edc87e544867ac800"),
            new AesXtsTestCase()
                .addKey("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0")
                .addKey("bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0afaeadacabaaa9a8a7a6a5a4a3a2a1a0")
                .addTweak("9a785634120000000000000000000000")
                .addInput("000102030405060708090a0b0c0d0e0f10")
                .addCipherText("7f117752cc598a8b0d81d88af9f9bec800"),
            new AesXtsTestCase()
                .addKey("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0")
                .addKey("bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0afaeadacabaaa9a8a7a6a5a4a3a2a1a0")
                .addTweak("9a785634120000000000000000000000")
                .addInput("000102030405060708090a0b0c0d0e0f101112131415")
                .addCipherText("75e8188bcce59ada939f57de2cb9a489c30ca8f2ed00"),
            new AesXtsTestCase()
                .addKey("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0")
                .addKey("bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0afaeadacabaaa9a8a7a6a5a4a3a2a1a0")
                .addTweak("9a785634120000000000000000000000")
                .addInput("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e")
                .addCipherText("581ea1fee5516ad432ddebe75fd27c6fc30ca8f2ed57307edc87e544867a00"),
            new AesXtsTestCase()
                .addKey("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0")
                .addKey("bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0afaeadacabaaa9a8a7a6a5a4a3a2a1a0")
                .addTweak("9a785634120000000000000000000000")
                .addInput("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e")
                .addCipherText("581ea1fee5516ad432ddebe75fd27c6fc30ca8f2ed57307edc87e544867a00"),
            new AesXtsTestCase()
                .addKey("1b278f1086f30d9f3b18a8dc2a258efea106b45bd18c760e360ba3c69859de47")
                .addKey("1c1c73d5f3de874486fa1d2c0573dfec5567d07468649a24dc9e72f421fa0b83")
                .addTweak("28000000000000000000000000000000")
                .addInput("208e5d0fa5ce130b294265e6430b98772eaae086a922391b98f0dec159a4f9c0")
                .addCipherText("7b8dc9d2c9bc031fa40ba63cce59428e09fccc48a96a95da120a592d2da9ff00"),
            new AesXtsTestCase()
                .addKey("1338d7d3d66137abf00c8f33050cff7e0a6fa10ff2e2bd860119dfa68ee815c4")
                .addKey("4aa1bfc76f2e084d81b862c05aae29711bf167fff7432a7b9c5899ab069fff0f")
                .addTweak("54000000000000000000000000000000")
                .addInput("922489de313fceb72a5ef2594d49eeb908afec966e89f0c7fbb4f6d37a559294")
                .addInput("2c53e3a65b37193d693467006595f811")
                .addCipherText("6f229c1b60833e2a50a041b360d99181a679f1361a011bf37b2e1565fda4a6b9")
                .addCipherText("22e5aabda21b167c030935e843d60c00"),
            new AesXtsTestCase()
                .addKey("1338d7d3d66137abf00c8f33050cff7e0a6fa10ff2e2bd860119dfa68ee815c4")
                .addKey("4aa1bfc76f2e084d81b862c05aae29711bf167fff7432a7b9c5899ab069fff0f")
                .addTweak("54000000000000000000000000000000")
                .addInput("922489de313fceb72a5ef2594d49eeb908afec966e89f0c7fbb4f6d37a559294")
                .addInput("2c53e3a65b37193d69346700")
                .addCipherText("6f229c1b60833e2a50a041b360d99181a679f1361a011bf37b2e1565fda4a6b9")
                .addCipherText("a679f1361a011bf37b2e1500"));
    tests.forEach(AesXtsTestCase::checkNegative);
  }

  private static SecretKeySpec getAnAesXtsKey() {
    final String keyHex =
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F";
    return new SecretKeySpec(TestUtil.decodeHex(keyHex), "AES-XTS");
  }

  private static IvParameterSpec getATweak() {
    final String tweakHex = "000102030405060708090A0B0C0D0E0F";
    return new IvParameterSpec(TestUtil.decodeHex(tweakHex));
  }

  @Test
  public void givenClobberedBuffers_whenDoFinal_ExpectPlaintext() throws Exception {
    final SecretKeySpec key = getAnAesXtsKey();
    final IvParameterSpec tweak = getATweak();
    // the first 32 bytes is input and the last 32 bytes is output.
    final byte[] buffer = new byte[16 * 3];
    final Cipher cipher = getAesXtsCipher();
    cipher.init(Cipher.ENCRYPT_MODE, key, tweak);
    int cipherLen = cipher.doFinal(buffer, 0, 32, buffer, 16);
    assertEquals(32, cipherLen);
    // the first 16 bytes should be untouched.
    for (int i = 0; i != 16; i++) {
      assertEquals(0, buffer[i]);
    }
    cipher.init(Cipher.DECRYPT_MODE, key, tweak);
    assertArrayEquals(new byte[32], cipher.doFinal(buffer, 16, 32));
  }

  @Test
  public void givenValidInputsSameBuffer_whenDoFinal_ExpectPlaintext() throws Exception {
    final Cipher cipher = getAesXtsCipher();
    final SecretKeySpec sks = getAnAesXtsKey();
    final String data16Bytes = "000102030405060708090A0B0C0D0E0F1011121314151617";
    final byte[] input = TestUtil.decodeHex(data16Bytes);
    final IvParameterSpec tweak = getATweak();
    cipher.init(Cipher.ENCRYPT_MODE, sks, tweak);
    int outLen = cipher.doFinal(input, 0, input.length, input, 0);
    assertEquals(24, outLen);
    assertEquals(
        "770407BAC58070C22A0D2B1C8B0AD644B82298441F93D2A0",
        Hex.encodeHexString(input).toUpperCase());

    cipher.init(Cipher.DECRYPT_MODE, sks, tweak);
    outLen = cipher.doFinal(input, 0, input.length, input, 0);
    assertEquals(24, outLen);
    assertEquals(data16Bytes, Hex.encodeHexString(input).toUpperCase());
  }

  @Test
  public void givenValidInputsBuffer_whenDoFinal_ExpectPlaintext() throws Exception {
    final Cipher cipher = getAesXtsCipher();
    final SecretKeySpec sks = getAnAesXtsKey();
    final String data16Bytes = "000102030405060708090A0B0C0D0E0F1011121314151617";
    final byte[] input = TestUtil.decodeHex(data16Bytes);
    final IvParameterSpec tweak = getATweak();
    cipher.init(Cipher.ENCRYPT_MODE, sks, tweak);
    final byte[] cipherText = cipher.doFinal(input);
    assertEquals(24, cipherText.length);
    assertEquals(
        "770407BAC58070C22A0D2B1C8B0AD644B82298441F93D2A0",
        Hex.encodeHexString(cipherText).toUpperCase());

    cipher.init(Cipher.DECRYPT_MODE, sks, tweak);
    final byte[] plainText = cipher.doFinal(cipherText);
    assertEquals(24, plainText.length);
    assertEquals(data16Bytes, Hex.encodeHexString(plainText).toUpperCase());
  }

  @Test
  public void givenShortOutputBufferForXts_whenDoFinal_expectException() throws Exception {
    final Cipher cipher = getAesXtsCipher();
    cipher.init(
        Cipher.ENCRYPT_MODE,
        new SecretKeySpec(new byte[64], "AES-XTS"),
        new IvParameterSpec(new byte[16]));
    assertThrows(
        ShortBufferException.class, () -> cipher.doFinal(new byte[16], 0, 16, new byte[15], 0));
  }

  @Test
  public void givenInvalidInputSizeForXts_whenGetOutPutSize_expectException() throws Exception {
    final Cipher cipher = getAesXtsCipher();
    cipher.init(
        Cipher.ENCRYPT_MODE,
        new SecretKeySpec(new byte[64], "AES-XTS"),
        new IvParameterSpec(new byte[16]));
    assertThrows(IllegalArgumentException.class, () -> cipher.getOutputSize(15));
  }

  @Test
  public void givenInitializedXtsCipher_testGetIvAndParam() throws Exception {
    final Cipher cipher = getAesXtsCipher();
    assertNull(cipher.getIV());
    cipher.init(
        Cipher.ENCRYPT_MODE,
        new SecretKeySpec(new byte[64], "AES-XTS"),
        new IvParameterSpec(new byte[16]));
    assertTrue(Arrays.areEqual(new byte[16], cipher.getIV()));
    assertNull(cipher.getParameters());
  }

  @Test
  public void testUnsupportedOperationsCases() throws Exception {
    final Cipher cipher = getAesXtsCipher();
    final byte[] keyBytes = new byte[64];
    final SecretKeySpec key = new SecretKeySpec(keyBytes, "AES-XTS");
    assertThrows(UnsupportedOperationException.class, () -> cipher.init(Cipher.ENCRYPT_MODE, key));
    final AlgorithmParameters ap = AlgorithmParameters.getInstance("AES");
    assertThrows(
        UnsupportedOperationException.class, () -> cipher.init(Cipher.ENCRYPT_MODE, key, ap));
    assertThrows(
        UnsupportedOperationException.class,
        () -> cipher.init(Cipher.WRAP_MODE, key, new IvParameterSpec(new byte[16])));
    cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(new byte[16]));
    assertThrows(UnsupportedOperationException.class, () -> cipher.update(new byte[16]));
    assertThrows(
        UnsupportedOperationException.class,
        () -> cipher.update(new byte[32], 0, 16, new byte[16], 0));
  }

  @Test
  public void testIllegalStateCases() {
    final Cipher cipher = getAesXtsCipher();
    final byte[] keyBytes = new byte[64];
    // use the cipher when it's not initialized
    assertThrows(
        IllegalStateException.class,
        () -> cipher.doFinal(keyBytes, 0, keyBytes.length, keyBytes, 0));
  }

  @Test
  public void testCannotReuseKeyTweakPairForEncryption() throws Exception {
    final Cipher cipher = getAesXtsCipher();
    // re-use the cipher with the same key and tweak for encryption
    cipher.init(Cipher.ENCRYPT_MODE, getAnAesXtsKey(), getATweak());
    cipher.doFinal(new byte[16]);

    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> cipher.init(Cipher.ENCRYPT_MODE, getAnAesXtsKey(), getATweak()));
  }

  @SuppressWarnings("serial")
  private static class CustomParam implements AlgorithmParameterSpec {}

  @Test
  public void testInvalidAlgorithmParameterExceptionCases() {
    final Cipher cipher = getAesXtsCipher();
    final byte[] keyBytes = new byte[64];
    final SecretKeySpec sks = new SecretKeySpec(keyBytes, "AES-XTS");
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> cipher.init(Cipher.ENCRYPT_MODE, sks, new CustomParam()));
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> cipher.init(Cipher.ENCRYPT_MODE, sks, new IvParameterSpec(keyBytes)));
  }

  @SuppressWarnings("serial")
  private static class CustomKey implements Key {

    @Override
    public String getAlgorithm() {
      return null;
    }

    @Override
    public String getFormat() {
      return null;
    }

    @Override
    public byte[] getEncoded() {
      return new byte[0];
    }
  }

  @SuppressWarnings("serial")
  private static class CustomSecretKey implements SecretKey {
    String format;
    byte[] encoding;

    CustomSecretKey(String format, byte[] encoding) {
      this.format = format;
      this.encoding = encoding;
    }

    @Override
    public String getAlgorithm() {
      return null;
    }

    @Override
    public String getFormat() {
      return format;
    }

    @Override
    public byte[] getEncoded() {
      return encoding;
    }
  }

  @Test
  public void testInvalidKeyExceptionCases() {
    final Cipher cipher = getAesXtsCipher();
    final IvParameterSpec tweak = new IvParameterSpec(new byte[16]);
    assertThrows(
        InvalidKeyException.class, () -> cipher.init(Cipher.ENCRYPT_MODE, new CustomKey(), tweak));
    assertThrows(
        InvalidKeyException.class,
        () -> cipher.init(Cipher.ENCRYPT_MODE, new CustomSecretKey("DUMMY", null), tweak));
    assertThrows(
        InvalidKeyException.class,
        () -> cipher.init(Cipher.ENCRYPT_MODE, new CustomSecretKey("RAW", null), tweak));
    assertThrows(
        InvalidKeyException.class,
        () -> cipher.init(Cipher.ENCRYPT_MODE, new CustomSecretKey("RAW", new byte[10]), tweak));
  }
}
