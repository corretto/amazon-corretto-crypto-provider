// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

public class SHA384Test extends BaseSHATest {

  public SHA384Test() {
    super(
        "SHA-384",
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        "testing",
        "cf4811d74fd40504674fc3273f824fa42f755b9660a2e902b57f1df74873db1a91a037bcee65f1a88ecd1ef57ff254c9",
        "SHA384ShortMsg.rsp.gz",
        "SHA384LongMsg.rsp.gz");
  }
}
