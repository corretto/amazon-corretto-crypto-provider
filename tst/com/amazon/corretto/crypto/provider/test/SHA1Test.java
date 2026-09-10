// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

public class SHA1Test extends BaseSHATest {

  public SHA1Test() {
    super(
        "SHA-1",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "testing",
        "dc724af18fbdd4e59189f5fe768a5f8311527050",
        "SHA1ShortMsg.rsp.gz",
        "SHA1LongMsg.rsp.gz");
  }
}
