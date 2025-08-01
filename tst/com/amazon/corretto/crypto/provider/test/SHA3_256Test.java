// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

public class SHA3_256Test extends BaseSHATest {

  private static final String ALGORITHM = "SHA3-256";
  private static final String NULL_DIGEST =
      "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
  private static final String TEST_VECTOR =
      "7f5979fb78f082e8b1c676635db8795c4ac6faba03525fb708cb5fd68fd40c5e";
  private static final String CAVP_SHORT_FILE = "SHA3_256ShortMsg.rsp.gz";
  private static final String CAVP_LONG_FILE = "SHA3_256LongMsg.rsp.gz";

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
