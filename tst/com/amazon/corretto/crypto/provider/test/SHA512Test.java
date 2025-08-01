// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

public class SHA512Test extends BaseSHATest {

  private static final String ALGORITHM = "SHA-512";
  private static final String NULL_DIGEST =
      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
  private static final String TEST_VECTOR =
      "521b9ccefbcd14d179e7a1bb877752870a6d620938b28a66a107eac6e6805b9d0989f45b5730508041aa5e710847d439ea74cd312c9355f1f2dae08d40e41d50";
  private static final String CAVP_SHORT_FILE = "SHA512ShortMsg.rsp.gz";
  private static final String CAVP_LONG_FILE = "SHA512LongMsg.rsp.gz";

  @Override
  protected String getAlgorithm() {
    return ALGORITHM;
  }

  @Override
  protected String getNullDigest() {
    return NULL_DIGEST;
  }

  @Override
  protected String getTestVector() {
    return TEST_VECTOR;
  }

  @Override
  protected String getCavpShortFile() {
    return CAVP_SHORT_FILE;
  }

  @Override
  protected String getCavpLongFile() {
    return CAVP_LONG_FILE;
  }
}
