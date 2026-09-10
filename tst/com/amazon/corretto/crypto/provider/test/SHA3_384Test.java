// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

public class SHA3_384Test extends BaseSHATest {

  public SHA3_384Test() {
    super(
        "SHA3-384",
        "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
        "testing",
        "e15a44d4e12ac138db4b8d77e954d78d94de4391ec2d1d8b2b8ace1a2f4b3d2fb9efd0546d6fcafacbe5b1640639b005",
        "SHA3_384ShortMsg.rsp.gz",
        "SHA3_384LongMsg.rsp.gz");
  }
}
