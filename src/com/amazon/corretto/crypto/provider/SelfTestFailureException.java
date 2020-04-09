// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

public class SelfTestFailureException extends RuntimeCryptoException {
    private static final long serialVersionUID = 1L;

    public SelfTestFailureException() {
    }

    public SelfTestFailureException(String message) {
        super(message);
    }

    public SelfTestFailureException(Throwable cause) {
        super(cause);
    }

    public SelfTestFailureException(String message, Throwable cause) {
        super(message, cause);
    }

    public SelfTestFailureException(String message, Throwable cause, boolean enableSuppression,
            boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

}
