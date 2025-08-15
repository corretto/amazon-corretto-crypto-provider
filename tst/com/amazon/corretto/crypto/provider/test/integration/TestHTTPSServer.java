// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test.integration;

import static com.amazon.corretto.crypto.provider.test.integration.HTTPSTestParameters.SUPER_SECURE_PASSWORD;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import com.amazon.corretto.crypto.provider.test.TestUtil;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.StringJoiner;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * This class launches a simple test HTTPS server for use in the LocalHTTPSIntegrationTest.
 *
 * <p>This server runs as an independent process to allow it to have a different set of security
 * providers from the test suite itself.
 */
public class TestHTTPSServer {
  private static class KeyAndCert {
    X509Certificate[] certificateChain;
    PrivateKey privateKey;

    public KeyAndCert(Certificate[] certificateChain, PrivateKey privateKey) {
      this.certificateChain = new X509Certificate[certificateChain.length];

      for (int i = 0; i < certificateChain.length; i++) {
        this.certificateChain[i] = (X509Certificate) certificateChain[i];
      }

      this.privateKey = privateKey;
    }
  }

  // This key manager selects which certificate to use based on the SNI hostname presented - this
  // allows us to try
  // multiple key sizes and signature methods using the same server port.
  private static class SNIKeyManager extends X509ExtendedKeyManager {
    KeyStore keyStore;
    ConcurrentHashMap<String, KeyAndCert> keyCache = new ConcurrentHashMap<>();

    private SNIKeyManager() throws Exception {
      keyStore = KeyStore.getInstance("JKS");
      try (InputStream is = SNIKeyManager.class.getResourceAsStream("test_private_keys.jks")) {
        if (is == null) {
          throw new IOException("Can't load private key store");
        }
        keyStore.load(is, SUPER_SECURE_PASSWORD);
      }
    }

    private KeyAndCert getKey0(String hostname) {
      try {
        Certificate[] certChain = keyStore.getCertificateChain(hostname);

        if (certChain == null) {
          return null;
        }

        PrivateKey key = (PrivateKey) keyStore.getKey(hostname, SUPER_SECURE_PASSWORD);

        return new KeyAndCert(certChain, key);
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    }

    private KeyAndCert getKey(String hostname) {
      return keyCache.computeIfAbsent(hostname, this::getKey0);
    }

    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
      ExtendedSSLSession session = (ExtendedSSLSession) engine.getHandshakeSession();

      for (SNIServerName name : session.getRequestedServerNames()) {
        if (name instanceof SNIHostName) {
          String hostname = ((SNIHostName) name).getAsciiName();
          if (getKey(hostname) != null) {
            return hostname;
          }
        }
      }

      return null;
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
      return new String[0];
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
      return null;
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
      throw new UnsupportedOperationException();
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
      throw new UnsupportedOperationException();
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
      KeyAndCert key = getKey(alias);

      if (key != null) {
        return key.certificateChain;
      } else {
        return null;
      }
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
      KeyAndCert key = getKey(alias);

      if (key != null) {
        return key.privateKey;
      } else {
        return null;
      }
    }
  }

  private static void runServer() throws Exception {
    KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null, null);

    TrustManagerFactory tmf =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init(keyStore);

    String tlsVersion = TestUtil.JAVA_VERSION == 10 ? "TLS" : "TLSv1.3";
    SSLContext sslContext = SSLContext.getInstance(tlsVersion);
    sslContext.init(new KeyManager[] {new SNIKeyManager()}, tmf.getTrustManagers(), null);

    HttpsServer server = HttpsServer.create();
    server.bind(new InetSocketAddress(0), 10);

    SSLEngine sampleEngine = SSLContext.getDefault().createSSLEngine();
    String[] cipherSuites = sampleEngine.getSupportedCipherSuites();
    String[] protocols = sampleEngine.getSupportedProtocols();
    SSLParameters sslParams = SSLContext.getDefault().getDefaultSSLParameters();
    sslParams.setNeedClientAuth(false);
    sslParams.setWantClientAuth(false);
    sslParams.setProtocols(protocols);
    // We'll let the client decide which protocols and cipher suites to test, by enabling support
    // for _everything_, including ones that are obviously a bad idea.
    sslParams.setCipherSuites(cipherSuites);

    server.setHttpsConfigurator(
        new HttpsConfigurator(sslContext) {
          @Override
          public void configure(HttpsParameters params) {
            // Setting the SSL parameters causes everything else to be ignored.
            params.setSSLParameters(sslParams);
          }
        });

    server.createContext(
        "/",
        new HttpHandler() {
          @Override
          public void handle(HttpExchange exchange) throws IOException {
            exchange.sendResponseHeaders(200, 0);
            exchange.close();
          }
        });

    ExecutorService es = Executors.newCachedThreadPool();

    server.setExecutor(
        task ->
            es.submit(
                () -> {
                  try {
                    task.run();
                  } catch (Throwable t) {
                    t.printStackTrace();
                  }
                }));
    server.start();

    // Since we ask to bind to an arbitrary port (to avoid conflicts with whatever else might be
    // running),
    // communicate this port back to the unit test over stdout
    System.out.println("PORT=" + server.getAddress().getPort());
  }

  public static void main(String[] args) throws Exception {
    if (Boolean.parseBoolean(System.getProperty("accp"))) {
      AmazonCorrettoCryptoProvider.install();
    }

    Security.addProvider(new BouncyCastleProvider());
    runServer();

    // Die after 10 minutes in case the test failed to terminate us
    while (true) Thread.sleep(TimeUnit.MINUTES.toMillis(10));

    // Runtime.getRuntime().halt(1);
  }

  // The following code runs in the parent process and manages launching and shutting down the
  // server subprocesses

  private static Process launchSubJava(String... args) throws IOException {
    // In Java 9 we can't easily get at the classpath, for now we'll just grab classpath URLs from
    // specific classes
    // of interest.

    Class<?>[] klasses =
        new Class<?>[] {
          TestHTTPSServer.class, BouncyCastleProvider.class, AmazonCorrettoCryptoProvider.class
        };
    HashSet<URL> classpathElements = new HashSet<>();

    for (Class<?> klass : klasses) {
      classpathElements.add(klass.getProtectionDomain().getCodeSource().getLocation());
    }

    URL[] classpath = classpathElements.toArray(new URL[0]);

    ArrayList<String> javaInvocation = new ArrayList<>();
    StringJoiner classpathString = new StringJoiner(":", "", "");
    for (URL element : classpath) {
      classpathString.add(element.toString());
    }

    // TODO see if this works on windows
    javaInvocation.add(System.getProperty("java.home") + "/bin/java");
    javaInvocation.add("-cp");
    javaInvocation.add(classpathString.toString());
    javaInvocation.add("-Djava.library.path=" + System.getProperty("java.library.path"));
    // NOTE: the below debug parameter is useful when debugging server-side
    //       issues that occur before the TLS handshake has completed (e.g.
    //       certificate signature mismatches) and test log utilitiess at
    //       the HTTPS level are available.
    //
    //       javaInvocation.add("-Djavax.net.debug=all");
    javaInvocation.addAll(Arrays.asList(args));

    return Runtime.getRuntime().exec(javaInvocation.toArray(new String[0]));
  }

  /**
   * Launches a thread that reads lines from is and passes them to lineProcessor
   *
   * @param threadName Thread name
   * @param is Input stream to read from
   * @param lineProcessor Callback to receive lines of output
   */
  private static void watchStream(
      String threadName, InputStream is, Consumer<String> lineProcessor) {
    Thread t =
        new Thread(
            () -> {
              try (BufferedReader br =
                  new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                String line;
                while (null != (line = br.readLine())) {
                  lineProcessor.accept(line);
                }
              } catch (Exception e) {
                e.printStackTrace();
                return;
              } finally {
                try {
                  is.close();
                } catch (IOException e) {
                  // can't do anything about it
                }
              }
            });
    t.setName(threadName);
    t.setDaemon(true);
    t.start();
  }

  public static TestHTTPSServer launch(boolean accp) throws Exception {
    CompletableFuture<Integer> portCompletion = new CompletableFuture<>();

    Process process = launchSubJava("-Daccp=" + accp, TestHTTPSServer.class.getCanonicalName());

    watchStream(
        "HTTPS server stdout watcher",
        process.getInputStream(),
        line -> {
          if (line.startsWith("PORT=")) {
            int port = Integer.parseInt(line.substring(5));
            portCompletion.complete(port);
          }
          System.out.println(line);
        });
    watchStream("HTTPS server stderr watcher", process.getErrorStream(), System.err::println);

    try {
      // portCompletion.get waits for the subprocess to report its listening port before we proceed
      // further
      return new TestHTTPSServer(process, portCompletion.get(10, TimeUnit.SECONDS));
    } catch (TimeoutException e) {
      process.destroyForcibly();

      throw new RuntimeException("HTTPS server startup timed out after 10 seconds");
    }
  }

  private final Process childProcess;
  private final int port;

  private TestHTTPSServer(Process childProcess, int port) {
    this.childProcess = childProcess;
    this.port = port;
  }

  public int getPort() {
    return port;
  }

  public Process getProcess() {
    return childProcess;
  }

  public void kill() {
    childProcess.destroyForcibly();
  }

  public boolean isAlive() {
    return getProcess().isAlive();
  }
}
