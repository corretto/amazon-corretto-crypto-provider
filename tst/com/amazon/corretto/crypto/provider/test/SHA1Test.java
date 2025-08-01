// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

public class SHA1Test extends BaseSHATest {

  private static final String ALGORITHM = "SHA-1";
  private static final String NULL_DIGEST = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
  private static final String TEST_VECTOR = "dc724af18fbdd4e59189f5fe768a5f8311527050";
  private static final String CAVP_SHORT_FILE = "SHA1ShortMsg.rsp.gz";
  private static final String CAVP_LONG_FILE = "SHA1LongMsg.rsp.gz";

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
