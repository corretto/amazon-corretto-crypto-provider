// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

public class SHA3_256Test extends BaseSHATest {

  public SHA3_256Test() {
    super(
        "SHA3-256",
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        "testing",
        "7f5979fb78f082e8b1c676635db8795c4ac6faba03525fb708cb5fd68fd40c5e",
        "SHA3_256ShortMsg.rsp.gz",
        "SHA3_256LongMsg.rsp.gz");
  }
}
