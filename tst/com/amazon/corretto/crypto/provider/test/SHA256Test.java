// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

public class SHA256Test extends BaseSHATest {

  public SHA256Test() {
    super(
        "SHA-256",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "testing",
        "cf80cd8aed482d5d1527d7dc72fceff84e6326592848447d2dc0b0e87dfc9a90",
        "SHA256ShortMsg.rsp.gz",
        "SHA256LongMsg.rsp.gz");
  }
}
