// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

/**
 * This exists solely to implement the "provider method" as defined in @{link java.util.ServiceLoader} and is used to
 * permit easy and automatic registration of this as a JCE provider.
 */
public final class ServiceProviderFactory {
    private ServiceProviderFactory() {
        // Prevent instantiation
    }

    public static AmazonCorrettoCryptoProvider provider() {
        return AmazonCorrettoCryptoProvider.INSTANCE;
    }

}
