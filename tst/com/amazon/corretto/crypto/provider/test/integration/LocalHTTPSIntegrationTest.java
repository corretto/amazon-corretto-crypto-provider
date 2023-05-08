// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test.integration;

import static com.amazon.corretto.crypto.provider.test.integration.HTTPSTestParameters.SIGNATURE_METHODS_TO_TEST;
import static com.amazon.corretto.crypto.provider.test.integration.HTTPSTestParameters.SUPER_SECURE_PASSWORD;
import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import com.amazon.corretto.crypto.provider.test.TestResultLogger;
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
import javax.crypto.Cipher;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.SAME_THREAD)
public class LocalHTTPSIntegrationTest {
  private static Set<String> allCipherSuites;

  static {
    try {
      resetProviders();

      // Make sure we don't get some cipher suites that are only supported under BC in our list of
      // suites to test.
      // Currently no such suites seem to exist, but perhaps that might change in the future.
      allCipherSuites =
          new HashSet<>(
              Arrays.asList(SSLContext.getDefault().createSSLEngine().getSupportedCipherSuites()));
    } catch (Exception e) {
      throw new Error(e);
    }
  }

  private static void resetProviders() {
    Security.removeProvider("AmazonCorrettoCryptoProvider");
    Security.removeProvider("BC");
  }

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
        // We're not set up to provide ECDH-capable certificates; these certs require the key type
        // in the server
        // certificate and the key type in the parent CA cert to be different, which is not
        // currently covered
        // by the TestCertificateGenerator.
        continue;
      }

      for (String method : SIGNATURE_METHODS_TO_TEST) {
        if (!HTTPSTestParameters.suiteMatchesSignature(cipherSuite, method)) {
          // We generate our server certificates in such a way that the key type in the server
          // certificate
          // matches the key type used to sign the certificate. As such, this key type must _also_
          // match
          // the key required by the cipher suite in use. We can't use a server cert showing a DH
          // public key
          // with an RSA cipher suite, for example.
          continue;
        }

        List<Integer> keySizes = HTTPSTestParameters.keySizesForSignatureMethod(method);

        for (int size : keySizes) {
          // boolean flags: ACCP on server, BC on client
          params.add(new Object[] {true, true, cipherSuite, method, size});
          params.add(new Object[] {false, true, cipherSuite, method, size});
          params.add(new Object[] {true, false, cipherSuite, method, size});
          params.add(new Object[] {false, false, cipherSuite, method, size});
        }
      }
    }

    return params.toArray(new Object[0][]);
  }

  private static TrustManagerFactory trustManagerFactory;
  private static TestHTTPSServer withACCP, withoutACCP;

  @BeforeAll
  public static void launchServer() throws Exception {
    // Do this before setting up providers, as loading BC early in the provider chain (even without
    // ACCP) breaks
    // KeyStore.
    KeyStore keyStore = KeyStore.getInstance("JKS");
    try (InputStream is = TestHTTPSServer.class.getResourceAsStream("test_CA.jks")) {
      keyStore.load(is, SUPER_SECURE_PASSWORD);
    }
    trustManagerFactory =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    trustManagerFactory.init(keyStore);

    withoutACCP = TestHTTPSServer.launch(false);
    try {
      withACCP = TestHTTPSServer.launch(true);
    } catch (Throwable t) {
      withoutACCP.kill();
      throw t;
    }
  }

  @AfterAll
  public static void shutdown() {
    withoutACCP.kill();
    withACCP.kill();
  }

  @BeforeEach
  public void setup() throws Exception {
    resetProviders();

    if (!withoutACCP.isAlive() || !withACCP.isAlive()) {
      fail("Server died");
    }

    AmazonCorrettoCryptoProvider.install();

    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
    assertEquals(AmazonCorrettoCryptoProvider.INSTANCE, c.getProvider());
  }

  @AfterEach
  public void cleanup() throws Exception {
    resetProviders();
  }

  @ParameterizedTest(
      name = "ServerACCPEnabled({0}) BCEnabled({1}) Suite({2}) SignatureType({3}) KeyBits({4})")
  @MethodSource("data")
  public void test(
      boolean serverACCPEnabled, boolean bcEnabled, String suite, String signatureType, int keyBits)
      throws Exception {
    if (bcEnabled) {
      Security.insertProviderAt(new BouncyCastleProvider(), 2);
    }

    int port = serverACCPEnabled ? withACCP.getPort() : withoutACCP.getPort();

    HttpsURLConnection conn =
        (HttpsURLConnection) new URL("https://127.0.0.1:" + port).openConnection();
    // this has the side effect of disabling the default SNI logic
    // c.f. http://stackoverflow.com/a/36343704
    // we actually want this behavior here as we'll be setting the SNI hostname to something
    // different from the
    // actual URL hostname
    conn.setHostnameVerifier((hostname, session) -> true);

    SSLContext context = SSLContext.getInstance(HTTPSTestParameters.protocolFromSuite(suite));

    context.init(null, trustManagerFactory.getTrustManagers(), null);

    SSLSocketFactory baseFactory = context.getSocketFactory();

    // Set up a custom SSLSocketFactory to 1) force a particular cipher suite and 2) pass the
    // desired certificate
    // signature algorithm and key size as a SNI hostname
    SSLSocketFactory sf =
        new SSLSocketFactory() {
          @Override
          public String[] getDefaultCipherSuites() {
            return new String[] {suite};
          }

          @Override
          public String[] getSupportedCipherSuites() {
            return new String[] {suite};
          }

          @Override
          public Socket createSocket(Socket s, String host, int port, boolean autoClose)
              throws IOException {
            SSLSocket socket = (SSLSocket) baseFactory.createSocket(host, port);

            socket.setEnabledCipherSuites(getSupportedCipherSuites());

            SSLParameters parameters = socket.getSSLParameters();
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
            parameters.setServerNames(
                singletonList(new SNIHostName(signatureType + "." + keyBits)));
            parameters.setProtocols(new String[] {HTTPSTestParameters.protocolFromSuite(suite)});

            socket.setSSLParameters(parameters);

            return socket;
          }

          @Override
          public Socket createSocket(String host, int port)
              throws IOException, UnknownHostException {
            return createSocket(host, port, null, 0);
          }

          @Override
          public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
              throws IOException {
            Socket socket = new Socket(host, port, localHost, localPort);

            try {
              return createSocket(socket, host, port, true);
            } catch (Throwable t) {
              socket.close();
              throw t;
            }
          }

          @Override
          public Socket createSocket(InetAddress host, int port) throws IOException {
            return createSocket(host.toString(), port);
          }

          @Override
          public Socket createSocket(
              InetAddress address, int port, InetAddress localAddress, int localPort)
              throws IOException {
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
