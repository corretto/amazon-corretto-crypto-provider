// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.NATIVE_PROVIDER;
import static com.amazon.corretto.crypto.provider.test.TestUtil.decodeHex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.amazon.corretto.crypto.provider.HpkePrivateKey;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * HPKE test vectors adapted from Wycheproof at revision 11238a4ac5a4ae66d1a3e0dd9cb924ee50204c7a
 * (C2SP/Wycheproof contributors, Apache-2.0).
 *
 * <p>These ciphertexts were sealed under the expected ML-KEM implicit-rejection secret. Opening
 * them checks that malformed encapsulations use that secret, including a case that catches
 * strcmp-style early termination when comparing the encapsulation with its re-encryption.
 */
@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class HpkeRegressionTest {
  private static final byte[] INFO = "wycheproof hpke info".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] AAD = "wycheproof aad".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] PLAINTEXT =
      "Beauty is truth, truth beauty".getBytes(StandardCharsets.US_ASCII);

  public static Stream<Arguments> vectors() {
    return Stream.of(
        // hpke_mlkem768_decrypt_test.json, tcId 13.
        Arguments.of(
            HpkeTestSuite.MLKEM768,
            "all-zero encapsulation",
            "b8594e3b413f45aca6e8ec922fe0a08be1be04f54e68b87b8c50c5779fc4898e59f45695fb5781bb"
                + "7b30e657768d41f1332fedc2344fe85f268cb50799dc2d8f",
            new byte[HpkeTestSuite.MLKEM768.encLength],
            "dc258cbf78b11132d3cbc7a9ed948db222192ff186b29c72691f662476a1bef5bbb8e272805c0cfb"
                + "6cff5c00b3"),
        // hpke_mlkem768_decrypt_test.json, tcId 36.
        Arguments.of(
            HpkeTestSuite.MLKEM768,
            "strcmp comparison",
            "cbfc4405d1b2a3a386c94c25e0f2d5f5ee92cb0388ff4d6aa04223086d51c3fd24752da14c9fc3b8"
                + "ae0d9e4a8b1016b8d8fc69e229c03ea2ef08a4ae0cffc37f",
            decodeHex(
                "00e96c44eb5f5380d80b4cb05d608971a28fbe838b912b558bf9676c6c67c9692ed6ea063fc47b70"
                    + "d5d6004825c269b9cb8e68b5728d67f44844d97686a11154e3cbd4a6f9e47524d93d851bdce480d7"
                    + "762ded09be53d17cce3ee28dc5a06911c062b99b218355dd5822108c55e2c67f7ea0b74b6189b33b"
                    + "4589d8ff9d0c867d13edaaf1c5f724675320beda3e6acc673c048fa04a1b30f899227d5a555e08a4"
                    + "12a47b7db75eb118a8844a71b186880426f6bb6e77186d18e753cbcce93c9fb76c729875b4d473ee"
                    + "ca8dab9941969faef04df9ce3178e7341eab416d28bb7aee12bfb8f4c3df814eff45a0187329079a"
                    + "cfc41a8e8dba7b08d111f02e37a1d2b69e57eef808fcc6ae23385534a420a93dfb6a95c73e2f1016"
                    + "177c4fe9d3ced769e277293aaceded6d07efc7890eaa885bd1e73f9e5da2b9cfda0d44cbc9090705"
                    + "ac2ce3e7bcd7775b593c706e45ddc97d3a65d9b7e73673f9473df5bfec689671f73e7f6ee77c730a"
                    + "8ebda1f0b2c112a71904d6f28a51d8d479f8323fb485e722f5c4d5857e95989a9cbaf273efd04fc3"
                    + "cbde98baa9969e095e88accecfbd12ef2155497a5b15fe91a70d1106b91a568363bfc2d6736cc813"
                    + "8cbc41ddf1e54fd40511e27d89e2c26c027b63c156e2bbb998faaed3d72186f0cc626dad39a782dc"
                    + "da2087fd13a9498e10b41b685646a227ea1166a5632c195983f4aba2b718b4074030d57126d34c38"
                    + "349892007acbea9e393b967dc3146b270f080a1f0bee90d65a095a6352a7718ed1717a8025a2bd38"
                    + "c66d120baf4247676a1fe044a57ce268c078f8ff46cc26fe4f9c7a03d6467adacb8418d26273662b"
                    + "ce1f7bc00b906e0088e95dc0fb419e2232e85aac77b9e7cd563e604de5e1d3e9693dcd3b19865cf4"
                    + "250773691e7e0af9c2755cd31f49d1f96708f3ba2f0b98184525abb869e12d5cea0ac1740181a875"
                    + "035300b05a54b8d42ee3b4ae92b06e43cd807e2b096c977f23c61ef8c989c52ed83754076dea1323"
                    + "f639250bef61bdf903bf7961cec89ba6942d9d0647ac9c8195d93ed8abcedf25754644035719a5a0"
                    + "a1c8c0798912726a9a8258e4c10ae7485322ed9ba331f6f090c4b492a4fcf53d753cd34f28ec0443"
                    + "fce0724f43c89a3942169d5099a8f7430f38691ebce2e3fe4f600d82c7ccedf60673f8e5d4c1a9f8"
                    + "4b8b5b23f5ed63defb6a7205e0a8b105bdc6ff4568fc78cb4456b02fedb7f4c48f6fd6b69216a331"
                    + "9821039db40e19a31a0b0c9d471d5a7a73865d26f8be3595525b1ec4a8579efd07ea98e2602e2bff"
                    + "dfd8febc5c7b4c736d326b5030ccc6faf9420a9c156a8f4516b9fff675459dfdcd4ef85d7adbdffd"
                    + "60f4a39628e399cc752c2e99ab2f431dc765e7c9d206bfe32649fbef4ef48b1d7936fc74766d7243"
                    + "50ee2245a8d5f23fbc6c7ed8b57168ce1e864e49d7f8c475dcda140bd42473825b3c72eb8c547801"
                    + "88813011e1962a503f9b516e13226de6375b204733b0192183c8f55e870e61cf8947c3191790bc0b"
                    + "657bc43aebc9d86c"),
            "cc1258b353cb681b3a12067363eac5cde057824b86a1e1e95690bad12f8f1c67e960f76d64934692"
                + "cdc29afdc1"),
        // hpke_mlkem1024_decrypt_test.json, tcId 13.
        Arguments.of(
            HpkeTestSuite.MLKEM1024,
            "all-zero encapsulation",
            "26ae7545ebbf0fd474d8b57d28c0352d0af4b06bd83f77fb03fadd716b70bbd524ac63d723feee46"
                + "f70b5c9351fa6f2962cf4e959b9ededfa5a24e29b7ee7474",
            new byte[HpkeTestSuite.MLKEM1024.encLength],
            "6e00f232ac32237b1e3ef235d7b9236169c883b46c1f4bad84ccefc03bdffb2bc0ea6de91df66ad9"
                + "bc7921293b"),
        // hpke_mlkem1024_decrypt_test.json, tcId 36.
        Arguments.of(
            HpkeTestSuite.MLKEM1024,
            "strcmp comparison",
            "8247c17686a8bc0b3afebe6bed1df1dc3ff7fa07c3670f624930235f20aecb4353ece11faa61f47d"
                + "946ee501abb9a48029096de63b243a1794c4a760f98cc157",
            decodeHex(
                "001d80376f40a555c9590838e4dd953cfb9a30edf7768f0f35b298c69eb459a42e081f79b419391b"
                    + "14347254849f1ddeac6d03975f22c9bd0e7a27cef18432e1d42b75d3845130cec8cd2387007116f7"
                    + "b21f69d196eb3340a44d4b3d92b2acfa420ce4654063d0e739ffb9238990c117454ed017d33bd63b"
                    + "c1c2da9adc52cb0fa2dc90f6f7482e3072f4d620d65afab8e908943dd7a4e91ed4e12b9147656a8f"
                    + "e758abdfa2d5d2d810edb4409ab09332b9dddccdc6cabf8d89633c609a0a005af2f4fac6baf70315"
                    + "103825531f513f9fc9f6d088cf28b54ff6fba4725e6ee291131b778058a45ed49bea10c1aa0aed05"
                    + "796a3bc88a1a45bc63a01b3646521e7968bdb0eab72758a6f025411814013e123fe354484f4380a2"
                    + "18f6f0b6876bf4a225766890ab191b6ffdf84fc19521533b58cc518a5f40d7e2861e9a51c297e3ab"
                    + "fe8b36674a066bdbb52390b6e2c91d0a6e1ae66210f3e700344d1a75978945ac9ef7fe72a7c1f693"
                    + "9690cd33e11ef3a9efbb9dc3285254af07121758aad87d34a85231b63f23a6b81a2e5bd232c0138f"
                    + "f574417d2b1fcbde45b686ed6348da7bb2cef151285ee52f4e0e214139f812a68df69459706baf85"
                    + "e31a0073623c7faec1c0b99d86d34fd3a7145210c1870f37687f8d4c94849a22dd1099cd8c730969"
                    + "fcf8e1cc4c1af623f89bb0f2e3b6e4a4c37b6d4d7c8f66df8c384c66264e7a4b35e893cf7424642d"
                    + "b20a844aef74a12f1dd244bd331101486babee54b326440f9f9b97e1f1a603146b42b8266a05781e"
                    + "c8bfff57bab186973a9b7bffa60ff246a01d2c9259950e94e9df25dca30c59890280636dee43f835"
                    + "10ddf7de2a5f77a78854cde70ead0943bac7895ee10d363a9334a1d502c282671161a2355f1d4be9"
                    + "9a1f9f67e687b9851caf8a3db107940b1ab4481084f8a96053c6205a207ca19043f8d20090ef2455"
                    + "57c6b7c1bd2065d2db7f8343acdcd9f7341491c665a8842c19e19d12ab36b01ec68c95bfd9226aa1"
                    + "0370ea1b71f08b326f7817a96c53132d7b5004fa00ecf1d6204198fc785b05438bc687cba235e5c2"
                    + "211d8e1e1f211664f240c3c2e4f4a1990943ec83ad80141beceba6e31384c0aa148783872593c0ce"
                    + "9e002cb2af6de35845dc1fcd6e7d5da96b6e8cf3a4cab1d6490ad18203cdac1a77f608c8460d2123"
                    + "0ac8470f841c6c17f5a1faff871c27c5a9e0e93a20b5c1e17d8f7a5c74065ab192c33d08d0c60322"
                    + "6a01b9f5976e0f06625baa7f90554ee805d7ee242cb54d3183758bf948ea31024fa3aa368cfc8ba7"
                    + "df1474a4388e84e3f79617080a96ce3af88ce5e1b9ba02871c2e6a54d0fc05050295f5f9a638a63c"
                    + "51428bc935c7f539cdd90a5501b8832a3bea490657f026ec6745d4b30f518e6f4b2bee0afb65b34d"
                    + "f1d81a4751aed0865b9cb01f4cdc65cab3ee1b3e988b23c0f2c63cb16e305d4c7b69a2ebac8471d6"
                    + "d61412004bbbd4550debbf64c49f5975df1f4bef53281fbadda4a5fb7dfa63e7261499a74c7f3af2"
                    + "026a997c1fdcde6c07fb3ce720a450f9de6970d6121706245e4cd2332247c6cce84085afbf7fab4f"
                    + "7f1fa98626646630e48e2dab8cb21661c306a22ebd7243beb7fc3c6cf57088a40d05c2381fef655c"
                    + "42817f1bb95de7d20f38d02fc1e3b2d6852b2a8f3a4dd4a262ada59f48482e44468c10c0506368c3"
                    + "05ee4efc93d60adac26c13258739640890762077e771ecb57c01efbb895c65a9eb1a2c479f1ad743"
                    + "4377331738a2034840682de3ae673ce47e3e54172556a3a543066fd5e30473c33641ffe90144bbe1"
                    + "5d68b5e8ab9c063f48edb3a4480356e7a7ddef32c60f0edffcf1c5fef4eb488476794f42af7b66eb"
                    + "01b19bfba59cacd157d485037b2c383add0cf2ff727c1056a466930e46e3f081af429a45e5ccdfe8"
                    + "e0f3c210474eb0156744c7d5486f761910083b6a8fba1898a52b112b96b4b3387f2f3e4000aa0854"
                    + "781b029e8c01f3f09f0cd361eaaa56a89b2a054a1805248e89ddc32dc8a3e53333595686e4e7b076"
                    + "340076a29c1c0f4f1232af35527e8d35f887e7fe524991b5b74da3b02dc26f7227595c096fd40541"
                    + "b86e7f0705cebd4c2a134c14e8f9eef94fa609a305e6a429f290404f1043c1666387df4bafc2308d"
                    + "c4eb2539c01dedc23d9c2018a9c5cdec50475a8f8ee32d9d13d79b304dcf69b949be7877fab4752b"
                    + "45b9ee04622123db"),
            "cdefad6d1a0e260f3b275ce9237015c2841bf14cb7922ddad7454fd26d5832c5db05ad8171570f49"
                + "53d4bf0dfc"));
  }

  @ParameterizedTest(name = "{0}: {1}")
  @MethodSource("vectors")
  public void implicitRejectionAndFailedOpenRetry(
      final HpkeTestSuite suite,
      final String description,
      final String seedHex,
      final byte[] encapsulation,
      final String ciphertextHex)
      throws Exception {
    suite.assumeAvailable();
    final byte[] seed = decodeHex(seedHex);
    final byte[] ciphertext = decodeHex(ciphertextHex);
    assertEquals(suite.seedLength, seed.length);
    assertEquals(suite.encLength, encapsulation.length);
    final HpkePrivateKey privateKey = HpkePrivateKey.fromEncoded(suite.namedSpec(), seed);
    final Cipher recipient = Cipher.getInstance("HPKE", NATIVE_PROVIDER);
    recipient.init(
        Cipher.DECRYPT_MODE,
        privateKey,
        suite.spec().withInfo(INFO).withEncapsulation(encapsulation));

    final byte[] forged = ciphertext.clone();
    forged[forged.length - 1] ^= 1;
    recipient.updateAAD(AAD);
    assertThrows(AEADBadTagException.class, () -> recipient.doFinal(forged));
    // A failed Open keeps the sequence number but clears buffered input and AAD.
    recipient.updateAAD(AAD);
    assertArrayEquals(PLAINTEXT, recipient.doFinal(ciphertext));
  }
}
