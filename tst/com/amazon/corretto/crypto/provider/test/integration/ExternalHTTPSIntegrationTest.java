// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test.integration;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assumeMinimumVersion;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import javax.crypto.Cipher;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.net.URL;
import java.security.Security;
import java.util.ArrayList;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import com.amazon.corretto.crypto.provider.test.TestResultLogger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * This test confirms that loading AmazonCorrettoCryptoProvider, with or without BouncyCastle, does not break our ability to
 * connect to various public HTTPS servers.
 */
@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.SAME_THREAD)
public class ExternalHTTPSIntegrationTest {
    private static final String[] URLS = new String[] {
            "https://good.sca1a.amazontrust.com/",
            "https://good.sca2a.amazontrust.com/",
            "https://good.sca3a.amazontrust.com/",
            "https://good.sca4a.amazontrust.com/",
            "https://good.sca0a.amazontrust.com/",
            "https://www.amazon.com",
            "https://s3.amazonaws.com",
            "https://www.google.com",
            "https://example.com",
            "https://sha256.badssl.com/",
            "https://sha384.badssl.com/",
            "https://sha512.badssl.com/",
            "https://ecc256.badssl.com/",
            "https://ecc384.badssl.com/",
            "https://dh1024.badssl.com/",
            "https://dh2048.badssl.com/",
            "https://rsa2048.badssl.com/",
            "https://rsa8192.badssl.com/"
    };

    public static Object[][] data() {
        ArrayList<Object[]> cases = new ArrayList<>();

        for (String url : URLS) {
            // (enable bouncycastle, url)
            cases.add(new Object[] { false, url });
            cases.add(new Object[] { true, url });
        }

        return cases.toArray(new Object[0][]);
   }

    @AfterAll
    public static void teardown() {
        resetProviders();
    }

    @ParameterizedTest(name="HTTPS integration test: URL={1} BCEnabled={0}")
    @MethodSource("data")
    public void testHTTPSConnectivity(boolean useBouncyCastle, String urlStr) throws Exception {
        URL url = new URL(urlStr);

        resetProviders();

        // BC breaks KeyStore loading if it's in an early position in the security providers list:
        // http://bouncy-castle.1462172.n4.nabble.com/BC-1-54-quot-breaks-quot-SunJSSE-PKCS12-keystore-PBE-td4658064.html

        // As such we'll set up our trust manager (and load the CA certs) before we install BC
        CustomTrustManager customTrustManager = new CustomTrustManager();

        Security.insertProviderAt(AmazonCorrettoCryptoProvider.INSTANCE, 1);
        if (useBouncyCastle) {
            // Note also that BC cannot be installed as position 1, as it'll result in recursively invoking its own RNG
            // to perform initial seeding.
            BouncyCastleProvider bcProv = new BouncyCastleProvider();
            // There is a bug in versions of BouncyCastle prior to 1.61 related to PSS signatures in TLS with Java 11.
            // Thus, if our URL is "https://example.com" and BouncyCastle is enabled with an old version, then we skip
            // this test to avoid failures unrelated to ACCP.
            if ("https://example.com".equals(urlStr)) {
                assumeMinimumVersion("1.62", bcProv);
            }
            Security.insertProviderAt(bcProv, 2);
        }

        assertEquals(AmazonCorrettoCryptoProvider.INSTANCE, Cipher.getInstance("AES/GCM/NoPadding").getProvider());

        HttpsURLConnection connection = null;
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, new TrustManager[] {customTrustManager}, null);
        try {
            connection = (HttpsURLConnection)url.openConnection();
            connection.setSSLSocketFactory(context.getSocketFactory());
            connection.connect();
            // We don't actually care what the response code is. Just receiving it means that we successfully
            // negotiated a TLS session and are now speaking HTTP with the underlying server.
            assertTrue(connection.getResponseCode() > 0,
                    "Retrieved non-sensical response code: " + connection.getResponseCode());
        } finally {
            try {
                connection.getInputStream().close();
            } catch (Throwable t) {
                /* ignore exceptions in cleanup */
            }
            resetProviders();
        }
    }


    private static void resetProviders() {
        Security.removeProvider("BC");
        Security.removeProvider(AmazonCorrettoCryptoProvider.INSTANCE.getName());
    }

}
