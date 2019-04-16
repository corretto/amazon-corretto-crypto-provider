// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;

import java.security.MessageDigest;
import java.security.Security;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import org.junit.Test;

import com.amazon.corretto.crypto.provider.SelfTestStatus;

public class TestProviderInstallation {
    @Test
    public void testProviderInstallation() throws Exception {
        Security.removeProvider("AmazonCorrettoCryptoProvider");
        // verify that we actually removed it so we know whether install() worked
        assertFalse("AmazonCorrettoCryptoProvider".equals(MessageDigest.getInstance("SHA-256").getProvider().getName()));

        AmazonCorrettoCryptoProvider.install();

        assertEquals("AmazonCorrettoCryptoProvider", MessageDigest.getInstance("SHA-256").getProvider().getName());
    }

    @Test
    public void providerSelfTests() {
        SelfTestStatus testStatus = AmazonCorrettoCryptoProvider.INSTANCE.getSelfTestStatus();
        assertFalse(SelfTestStatus.FAILED.equals(testStatus));

        testStatus = AmazonCorrettoCryptoProvider.INSTANCE.runSelfTests();
        assertEquals(SelfTestStatus.PASSED, testStatus);
    }

    @Test
    public void testGetLoadingError() {
        assertNull(AmazonCorrettoCryptoProvider.INSTANCE.getLoadingError());
    }

    @Test
    public void testAssertHealthy() {
        AmazonCorrettoCryptoProvider.INSTANCE.assertHealthy();
    }
}
