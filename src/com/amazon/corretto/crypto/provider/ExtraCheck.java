// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

/**
 * This describes various extra safety checks which may be enabled in this library.
 * These checks may be computationally expensive and are almost never actually necessary.
 */
public enum ExtraCheck {
  /** Check private keys for internal consistency when possible. */
  PRIVATE_KEY_CONSISTENCY,
  /** After generation check key-pairs for internal consistency. */
  KEY_PAIR_GENERATION_CONSISTENCY
}
