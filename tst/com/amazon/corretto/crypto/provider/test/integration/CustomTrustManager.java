// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test.integration;

import static com.amazon.corretto.crypto.provider.test.integration.HTTPSTestParameters.SUPER_SECURE_PASSWORD;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * This just adds Amazon Trust roots to the default set of trusted CA root certificates, allowing us to connect to the
 * amazontrust.com test sites.
 */
class CustomTrustManager implements X509TrustManager {
    private final X509TrustManager defaultTrustManager;
    private final X509TrustManager amazonCATrustManager;

    public CustomTrustManager() throws Exception {
        String defaultAlgo = TrustManagerFactory.getDefaultAlgorithm();
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(defaultAlgo);
        tmf.init((KeyStore) null);
        defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];

        try (InputStream is = CustomTrustManager.class.getResourceAsStream("amazonca.jks")) {
            if (is == null) {
                throw new RuntimeException("Can't find amazonca.jks resource");
            }

            KeyStore keyStore = KeyStore.getInstance("jks");
            keyStore.load(is, SUPER_SECURE_PASSWORD);
            tmf = TrustManagerFactory.getInstance(defaultAlgo);
            tmf.init(keyStore);

            amazonCATrustManager = (X509TrustManager)tmf.getTrustManagers()[0];
        }
    }

    @Override public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        defaultTrustManager.checkClientTrusted(chain, authType);
    }

    @Override public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        try {
            defaultTrustManager.checkServerTrusted(chain, authType);
        } catch (Exception e) {
            amazonCATrustManager.checkServerTrusted(chain, authType);
        }
    }

    @Override public X509Certificate[] getAcceptedIssuers() {
        return defaultTrustManager.getAcceptedIssuers();
    }
}
