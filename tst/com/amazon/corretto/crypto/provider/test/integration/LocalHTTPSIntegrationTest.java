// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test.integration;

import static com.amazon.corretto.crypto.provider.test.integration.HTTPSTestParameters.SIGNATURE_METHODS_TO_TEST;
import static com.amazon.corretto.crypto.provider.test.integration.HTTPSTestParameters.SUPER_SECURE_PASSWORD;
import static java.util.Collections.singletonList;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import javax.crypto.Cipher;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;

@RunWith(Parameterized.class)
public class LocalHTTPSIntegrationTest {
    private static Set<String> allCipherSuites;

    static {
        try {
            resetProviders();

            // Make sure we don't get some cipher suites that are only supported under BC in our list of suites to test.
            // Currently no such suites seem to exist, but perhaps that might change in the future.
            allCipherSuites = new HashSet<>(
                    Arrays.asList(SSLContext.getDefault().createSSLEngine().getSupportedCipherSuites())
            );
        } catch (Exception e) {
            throw new Error(e);
        }
    }

    private static void resetProviders() {
        Security.removeProvider("AmazonCorrettoCryptoProvider");
        Security.removeProvider("BC");
    }

    @Parameterized.Parameters(name = "ServerAACPEnabled({0}) BCEnabled({1}) Suite({2}) SignatureType({3}) KeyBits({4})")
    public static Object[][] data() throws Exception {
        List<Object[]> params = new ArrayList<>();

        for (String cipherSuite : allCipherSuites) {
            if (cipherSuite.contains("_DES") || cipherSuite.contains("_EXPORT_")) {
                // these break even without AmazonCorrettoCryptoProvider
                continue;
            }

            if (cipherSuite.contains("_NULL_")) {
                // negotiation breaks with these as well
                continue;
            }

            if (cipherSuite.contains("_ECDH_")) {
                // We're not set up to provide ECDH-capable certificates; these certs require the key type in the server
                // certificate and the key type in the parent CA cert to be different, which is not currently covered
                // by the TestCertificateGenerator.
                continue;
            }

            String keyAlgorithm;

            if (cipherSuite.contains("ECDSA")) {
                keyAlgorithm = "ECDSA";
            } else if (cipherSuite.contains("DSS")) {
                keyAlgorithm = "DSA";
            } else if (cipherSuite.contains("RSA")) {
                keyAlgorithm = "RSA";
            } else {
                // unsupported
                continue;
            }

            for (String method : SIGNATURE_METHODS_TO_TEST) {
                if (!method.endsWith("with" + keyAlgorithm)) {
                    // We generate our server certificates in such a way that the key type in the server certificate
                    // matches the key type used to sign the certificate. As such, this key type must _also_ match
                    // the key required by the cipher suite in use. We can't use a server cert showing a DH public key
                    // with an RSA cipher suite, for example.
                    continue;
                }

                List<Integer> keySizes = HTTPSTestParameters.keySizesForSignatureMethod(method);

                for (int size: keySizes) {
                    // boolean flags: AACP on server, BC on client
                    params.add(new Object[] { true, true, cipherSuite, method, size });
                    params.add(new Object[] { false, true, cipherSuite, method, size });
                    params.add(new Object[] { true, false, cipherSuite, method, size });
                    params.add(new Object[] { false, false, cipherSuite, method, size });
                }
            }
        }

        return params.toArray(new Object[0][]);
    }

    private boolean serverAACPEnabled;
    private boolean bcEnabled;
    private String suite;
    private String signatureType;
    private int keyBits;
    private int port;

    private TrustManagerFactory trustManagerFactory;

    private static TestHTTPSServer withAACP, withoutAACP;

    @BeforeClass
    public static void launchServer() throws Exception {
        withoutAACP = TestHTTPSServer.launch(false);
        try {
            withAACP = TestHTTPSServer.launch(true);
        } catch (Throwable t) {
            withoutAACP.kill();
            throw t;
        }
    }

    @AfterClass
    public static void shutdown() {
        withoutAACP.kill();
        withAACP.kill();
    }

    public LocalHTTPSIntegrationTest(boolean serverAACPEnabled, boolean bcEnabled, String suite, String signatureType, int keyBits) {
        this.serverAACPEnabled = serverAACPEnabled;
        this.bcEnabled = bcEnabled;
        this.suite = suite;
        this.signatureType = signatureType;
        this.keyBits = keyBits;
    }

    @Before
    public void setup() throws Exception {
        resetProviders();

        if (!withoutAACP.isAlive() || !withAACP.isAlive()) {
            fail("Server died");
        }

        // Do this before setting up providers, as loading BC early in the provider chain (even without AACP) breaks
        // KeyStore.
        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (InputStream is = TestHTTPSServer.class.getResourceAsStream("test_CA.jks")) {
            keyStore.load(is, SUPER_SECURE_PASSWORD);
        }

        trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(keyStore);

        Security.insertProviderAt(AmazonCorrettoCryptoProvider.INSTANCE, 1);

        if (bcEnabled) {
            Security.insertProviderAt(new BouncyCastleProvider(), 2);
        }

        port = serverAACPEnabled ? withAACP.getPort() : withoutAACP.getPort();

        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        assertEquals(AmazonCorrettoCryptoProvider.INSTANCE, c.getProvider());
    }

    @After
    public void cleanup() throws Exception {
        resetProviders();
    }

    @Test
    public void test() throws Exception {
        HttpsURLConnection conn = (HttpsURLConnection) new URL("https://127.0.0.1:" + port).openConnection();
        // this has the side effect of disabling the default SNI logic
        // c.f. http://stackoverflow.com/a/36343704
        // we actually want this behavior here as we'll be setting the SNI hostname to something different from the
        // actual URL hostname
        conn.setHostnameVerifier((hostname, session) -> true);

        SSLContext context = SSLContext.getInstance("TLS");

        context.init(null, trustManagerFactory.getTrustManagers(), null);

        SSLSocketFactory baseFactory = context.getSocketFactory();

        // Set up a custom SSLSocketFactory to 1) force a particular cipher suite and 2) pass the desired certificate
        // signature algorithm and key size as a SNI hostname
        SSLSocketFactory sf = new SSLSocketFactory() {
            @Override public String[] getDefaultCipherSuites() {
                return new String[] { suite };
            }

            @Override public String[] getSupportedCipherSuites() {
                return new String[] { suite };
            }

            @Override public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws
                    IOException {
                SSLSocket socket = (SSLSocket)baseFactory.createSocket(host, port);

                socket.setEnabledCipherSuites(getSupportedCipherSuites());

                SSLParameters parameters = socket.getSSLParameters();
                parameters.setEndpointIdentificationAlgorithm("HTTPS");
                parameters.setServerNames(singletonList(new SNIHostName(signatureType + "." + keyBits)));

                socket.setSSLParameters(parameters);

                return socket;
            }

            @Override public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
                return createSocket(host, port, null, 0);
            }

            @Override public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws
                    IOException {
                Socket socket = new Socket(host, port, localHost, localPort);

                try {
                    return createSocket(socket, host, port, true);
                } catch (Throwable t) {
                    socket.close();
                    throw t;
                }
            }

            @Override public Socket createSocket(InetAddress host, int port) throws IOException {
                return createSocket(host.toString(), port);
            }

            @Override public Socket createSocket(
                    InetAddress address, int port, InetAddress localAddress, int localPort
            ) throws IOException {
                return createSocket(address.toString(), port, localAddress, localPort);
            }
        };

        conn.setSSLSocketFactory(sf);

        try {
            conn.connect();

            assertEquals(200, conn.getResponseCode());
        } finally {
            conn.disconnect();
        }
    }
}
