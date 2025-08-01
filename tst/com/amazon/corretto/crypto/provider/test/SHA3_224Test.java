// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

public class SHA3_224Test extends BaseSHATest {

  private static final String ALGORITHM = "SHA3-224";
  private static final String NULL_DIGEST = "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7";
  private static final String TEST_VECTOR = "04eaf0c175aa45299155aca3f97e41c2d684eb0978c9af6cd88c5a51";
  private static final String CAVP_SHORT_FILE = "SHA3_224ShortMsg.rsp.gz";
  private static final String CAVP_LONG_FILE = "SHA3_224LongMsg.rsp.gz";

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
