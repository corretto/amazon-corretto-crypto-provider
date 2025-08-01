// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

public class SHA256Test extends BaseSHATest {

  private static final String ALGORITHM = "SHA-256";
  private static final String NULL_DIGEST = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  private static final String TEST_VECTOR = "cf80cd8aed482d5d1527d7dc72fceff84e6326592848447d2dc0b0e87dfc9a90";
  private static final String CAVP_SHORT_FILE = "SHA256ShortMsg.rsp.gz";
  private static final String CAVP_LONG_FILE = "SHA256LongMsg.rsp.gz";

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
