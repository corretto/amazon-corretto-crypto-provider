// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

public class RuntimeCryptoException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public RuntimeCryptoException() {
    }

    public RuntimeCryptoException(String message) {
        super(message);
    }

    public RuntimeCryptoException(Throwable cause) {
        super(cause);
    }

    public RuntimeCryptoException(String message, Throwable cause) {
        super(message, cause);
    }

    public RuntimeCryptoException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

}
