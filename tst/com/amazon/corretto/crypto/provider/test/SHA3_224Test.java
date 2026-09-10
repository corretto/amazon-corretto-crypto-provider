// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

public class SHA3_224Test extends BaseSHATest {

  public SHA3_224Test() {
    super(
        "SHA3-224",
        "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
        "testing",
        "04eaf0c175aa45299155aca3f97e41c2d684eb0978c9af6cd88c5a51",
        "SHA3_224ShortMsg.rsp.gz",
        "SHA3_224LongMsg.rsp.gz");
  }
}
