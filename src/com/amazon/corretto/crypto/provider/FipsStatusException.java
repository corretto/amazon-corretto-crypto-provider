// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

@SuppressWarnings("serial")
public class FipsStatusException extends RuntimeCryptoException {
    public FipsStatusException(final String message) {
        super(message);
    }
}
