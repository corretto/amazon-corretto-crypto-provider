// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import static com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider.install;
import static com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider.INSTANCE;
import static com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider.PROVIDER_NAME;
import static com.amazon.corretto.crypto.provider.Loader.PROVIDER_VERSION_STR;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

public final class Agent {
    private final static String OPTION_ASSERT = "assert";

    public static void premain(final String options) {
        install();
        verify();
        if (OPTION_ASSERT.equals(options)) INSTANCE.assertHealthy();
    }

    private static void verify() {
        Provider provider = null;
        try {
            provider = Cipher.getInstance("AES/GCM/NoPadding").getProvider();
        }
        catch (NoSuchAlgorithmException e) { }
        catch (NoSuchPaddingException e) { }

        if (provider != null && provider.getName().equals(PROVIDER_NAME)) {
            System.err.println(PROVIDER_NAME + " version " + PROVIDER_VERSION_STR);
        }

        if (INSTANCE.getLoadingError() == null) {
            final SelfTestStatus selfTestStatus = INSTANCE.runSelfTests();
            System.err.println(PROVIDER_NAME + " self-check " + selfTestStatus);
        }
    }

}
