// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test.jdk17plus;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import com.amazon.corretto.crypto.provider.test.RecordingProvider;
import com.amazon.corretto.crypto.provider.test.TestResultLogger;
import com.amazon.corretto.crypto.provider.test.TestUtil;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.BiPredicate;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.BCSSLSocket;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * End-to-end proof that BouncyCastle's JSSE provider (BCJSSE) can source ML-KEM from ACCP over the
 * standard JCA when ACCP is installed as the top provider.
 *
 * <p>The path under test is BCJSSE -&gt; JcaTlsCrypto -&gt; KEMSpiUtil.createKEM(...) which, when
 * BCJSSE is left in its default (unpinned) configuration, calls {@code
 * javax.crypto.KEM.getInstance(kemName)} with no provider argument. That resolution follows normal
 * JCA provider precedence, so a foreign top provider that registers a KEM service under the
 * looked-up name serves the request. The corresponding KeyPairGenerator and KeyFactory calls are
 * unpinned in the same way. See bc-java {@code
 * tls/src/main/jdk17/org/bouncycastle/tls/crypto/impl/jcajce/KEMSpiUtil.java} line ~36.
 *
 * <p>Two BCJSSE runtime requirements make the delegation actually reachable:
 *
 * <ul>
 *   <li>the JDK must expose {@code javax.crypto.KEMSpi} -- JDK 21+ or a KEM-backported JDK 17 (BC's
 *       {@code SpiUtil.hasKEM()} flips on that class);
 *   <li>the bctls jar must contain KEMSpiUtil -- first shipped in BC 1.84.
 * </ul>
 *
 * When either is missing this test skips (rather than fails), so it is a positive-signal cross-JDK
 * probe. It also skips when ACCP itself was built without ML-KEM (ACCP's shipped Maven artifacts
 * omit ML-KEM; a local build with {@code -DTARGET_JDK_VERSION=17+} enables it). Two {@link
 * RecordingProvider} sniffers make the observation precise: one sits just above ACCP and counts the
 * ML-KEM KEM / KeyPairGenerator / KeyFactory lookups routed to that position, and a second sits
 * just above BC (below ACCP) as a negative control that must see no ML-KEM key-generation or
 * key-reconstruction lookups. A real TLS 1.3 handshake between two BCJSSE peers is what drives
 * those lookups.
 */
@ExtendWith(TestResultLogger.class)
// Each test mutates the global JCA provider list (installing two recorder sniffers plus real ACCP,
// BC, and BCJSSE) and asserts on lookups routed through them, so the tests must not run
// concurrently with each other or with any other provider-touching test. This mirrors the locking
// convention used by the other provider-mutating tests (e.g. TestProviderInstallation,
// MiscSingleThreadedTests).
@Execution(ExecutionMode.SAME_THREAD)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ_WRITE)
@ResourceLock(value = TestUtil.RESOURCE_PROVIDER, mode = ResourceAccessMode.READ_WRITE)
public class BouncyCastleJsseMlKemIntegrationTest {

  /** KEM algorithm name that BCJSSE looks up for either MLKEM768 group. */
  private static final String KEM_ALG = "ML-KEM-768";

  /**
   * Proves BCJSSE sources ML-KEM from ACCP across both TLS 1.3 group flavours and all three
   * parameter sets: the pure {@code MLKEM512/768/1024} groups, and the hybrid {@code
   * X25519MLKEM768} group -- which BCJSSE decomposes into an X25519 half and an ML-KEM-768 half,
   * with the ML-KEM half still taking the KEM API path. Each case runs a real TLS 1.3 handshake
   * with a RecordingProvider sniffer just above ACCP at the top of the provider list, then asserts
   * ACCP served the ML-KEM lookups and BC never generated or reconstructed an ML-KEM key.
   */
  @ParameterizedTest
  @ValueSource(strings = {"MLKEM512", "MLKEM768", "MLKEM1024", "X25519MLKEM768"})
  public void bcjsseSourcesMlKemFromAccp(String namedGroup) throws Exception {
    runHandshakeAndAssertAccpServedMlKem(namedGroup);
  }

  // ---------------------------------------------------------------------------
  // Driver
  // ---------------------------------------------------------------------------

  private void runHandshakeAndAssertAccpServedMlKem(String namedGroup) throws Exception {
    assumeMlKemDelegationReachable();

    final Provider[] saved = TestUtil.saveProviders();
    try {
      // Provider list under test, top to bottom:
      //   1. AccpRecorder -- passive sniffer; records the ML-KEM lookups routed to this position
      //   2. ACCP         -- actually serves them (the "top" functional provider)
      //   3. BcRecorder   -- passive sniffer; negative control, registered just after ACCP and
      //                      just before BC
      //   4. BC           -- serves anything ACCP does not, plus the "BC"-pinned cert operators
      //   5. JDK providers (and BCJSSE, appended last; it is looked up by name anyway)
      // The recorders serve nothing, so each sits directly in front of the real provider it
      // observes: a lookup ACCP satisfies at position 2 never reaches BcRecorder at position 3,
      // which is what makes BcRecorder a meaningful negative control (see the assertion below).
      final BiPredicate<String, String> mlKemServices =
          BouncyCastleJsseMlKemIntegrationTest::isMlKemService;
      final RecordingProvider accpRecorder = new RecordingProvider("AccpRecorder", mlKemServices);
      final RecordingProvider bcRecorder = new RecordingProvider("BcRecorder", mlKemServices);
      final Provider accp = AmazonCorrettoCryptoProvider.INSTANCE;
      final Provider bc = newBcProvider();

      // Build the exact ordering deterministically regardless of what was installed before.
      Security.removeProvider(accp.getName());
      Security.removeProvider(bc.getName());
      Security.insertProviderAt(accpRecorder, 1);
      Security.insertProviderAt(accp, 2);
      Security.insertProviderAt(bcRecorder, 3);
      Security.insertProviderAt(bc, 4);
      Security.addProvider(new BouncyCastleJsseProvider());

      final boolean negotiated = driveHandshake(namedGroup, accpRecorder, true);
      assertTrue(negotiated, "TLS 1.3 handshake should complete over " + namedGroup);

      // Positive signal: ACCP (via the recorder in front of it) served the handshake's ML-KEM.
      final int kem = accpRecorder.lookupsByType("KEM");
      final int kpg = accpRecorder.lookupsByType("KeyPairGenerator");
      final int kf = accpRecorder.lookupsByType("KeyFactory");
      assertTrue(
          kem + kpg + kf > 0,
          () ->
              "Expected BCJSSE to look up ML-KEM services via the JCA against the top provider, "
                  + "but no ML-KEM service was requested. AccpRecorder: "
                  + accpRecorder.summary());
      // A KEM lookup specifically is the strongest signal that the JEP-452 delegation path fired.
      assertTrue(
          kem > 0,
          () ->
              "Expected at least one KEM.getInstance(\""
                  + KEM_ALG
                  + "\") to hit the top provider during the handshake. AccpRecorder: "
                  + accpRecorder.summary());

      // Negative control: BC (position 4) must never generate or reconstruct an ML-KEM key, so the
      // KeyPairGenerator / KeyFactory scans must stop at ACCP (position 2) and never fall through
      // to BcRecorder (position 3). This transitively rules out BC serving the KEM too: with no
      // ML-KEM key of its own, BC has nothing to encapsulate or decapsulate with.
      //
      // KEM lookups are deliberately NOT asserted to be zero here. BCJSSE probes every provider for
      // every ML-KEM parameter set's KEM service when a TLS context initializes (capability
      // discovery -- BcRecorder sees all of ML-KEM-512/768/1024 even for a single-group handshake),
      // so KEM lookups reach BC regardless of provider order and cannot be driven to zero by
      // positioning. The actual encapsulation still runs through ACCP: newEncapsulator walks the
      // provider list with an ACCP-generated key and stops at ACCP before reaching BC.
      assertEquals(
          0,
          bcRecorder.lookupsByType("KeyPairGenerator"),
          () ->
              "BC must not generate an ML-KEM key while ACCP is above it. BcRecorder: "
                  + bcRecorder.summary());
      assertEquals(
          0,
          bcRecorder.lookupsByType("KeyFactory"),
          () ->
              "BC must not reconstruct an ML-KEM key while ACCP is above it. BcRecorder: "
                  + bcRecorder.summary());
    } finally {
      TestUtil.restoreProviders(saved);
    }
  }

  /**
   * The (type, algorithm) filter identifying the ML-KEM services this test tallies: the KEM,
   * KeyPairGenerator, and KeyFactory lookups whose algorithm name starts with "ML-KEM".
   */
  private static boolean isMlKemService(final String type, final String algorithm) {
    if (algorithm == null) {
      return false;
    }
    if (!algorithm.toUpperCase().startsWith("ML-KEM")) {
      return false;
    }
    return type.equals("KEM") || type.equals("KeyPairGenerator") || type.equals("KeyFactory");
  }

  private static Provider newBcProvider() throws ReflectiveOperationException {
    return (Provider)
        Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider")
            .getDeclaredConstructor()
            .newInstance();
  }

  // ---------------------------------------------------------------------------
  // BCJSSE runtime environment gate
  // ---------------------------------------------------------------------------

  /**
   * The KEM delegation path is only reachable when: the JDK exposes {@code javax.crypto.KEMSpi}
   * (JDK 21+ or a KEM-backported JDK 17); the bundled bctls carries KEMSpiUtil (BC >= 1.84); and
   * ACCP itself has ML-KEM (its shipped Maven artifacts do not). Missing any one of these skips.
   */
  private void assumeMlKemDelegationReachable() {
    assumeTrue(
        classPresent("javax.crypto.KEMSpi"),
        "javax.crypto.KEMSpi absent -- need JDK 21+ or KEM-backported JDK 17");

    // KEMSpiUtil is package-private, but Class.forName resolves package-private classes fine so
    // long as they are on the classpath; on an MR-jar aware JDK 17+ classloader this picks the
    // META-INF/versions/17 overlay automatically.
    assumeTrue(
        classPresent("org.bouncycastle.tls.crypto.impl.jcajce.KEMSpiUtil"),
        "bctls does not carry KEMSpiUtil -- need BC >= 1.84 in the multi-release jar for this JDK");

    boolean accpHasMlKem;
    try {
      KeyPairGenerator.getInstance(KEM_ALG, AmazonCorrettoCryptoProvider.INSTANCE);
      accpHasMlKem = true;
    } catch (Exception e) {
      accpHasMlKem = false;
    }
    assumeTrue(
        accpHasMlKem,
        "ACCP does not have ML-KEM enabled; rebuild with -DTARGET_JDK_VERSION=17 (or newer).");
  }

  private static boolean classPresent(String name) {
    try {
      Class.forName(name);
      return true;
    } catch (Throwable t) {
      return false;
    }
  }

  // ---------------------------------------------------------------------------
  // Handshake harness
  // ---------------------------------------------------------------------------

  /**
   * Drives one BCJSSE TLS 1.3 handshake pinned to {@code namedGroup} on both peers, on the loopback
   * interface. Uses a JKS keystore holding a self-signed RSA leaf so cert operations don't
   * intersect the KEM path being measured. Returns true when both peers completed handshake + echo.
   */
  private boolean driveHandshake(
      String namedGroup, RecordingProvider recorder, boolean expectAccpServesMlKem)
      throws Exception {
    // An RSA leaf is used purely to let the TLS 1.3 handshake authenticate so the ML-KEM key
    // exchange (the actual subject of this test) runs; the certificate's key type is otherwise
    // incidental. RSA is chosen because it maps to signature schemes every BCJSSE peer offers.
    final KeyPair rsa = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    final X509Certificate cert = buildSelfSignedCert(rsa);

    final KeyStore ks = KeyStore.getInstance("JKS");
    ks.load(null, null);
    final char[] pw = "test".toCharArray();
    ks.setKeyEntry("leaf", rsa.getPrivate(), pw, new X509Certificate[] {cert});

    final KeyStore ts = KeyStore.getInstance("JKS");
    ts.load(null, null);
    ts.setCertificateEntry("leaf", cert);

    final KeyManagerFactory kmf =
        KeyManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);
    kmf.init(ks, pw);
    final TrustManagerFactory tmf =
        TrustManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);
    tmf.init(ts);

    final SSLContext serverCtx =
        SSLContext.getInstance("TLSv1.3", BouncyCastleJsseProvider.PROVIDER_NAME);
    serverCtx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
    final SSLContext clientCtx =
        SSLContext.getInstance("TLSv1.3", BouncyCastleJsseProvider.PROVIDER_NAME);
    clientCtx.init(null, tmf.getTrustManagers(), null);

    final BCSSLParameters bcParams = new BCSSLParameters();
    bcParams.setProtocols(new String[] {"TLSv1.3"});
    bcParams.setNamedGroups(new String[] {namedGroup});

    final ExecutorService executor = Executors.newSingleThreadExecutor();
    try (SSLServerSocket srv =
        (SSLServerSocket)
            serverCtx
                .getServerSocketFactory()
                .createServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
      // BC exposes no server-socket-level parameter interface (there is no
      // BCSSLServerSocket); the named-group pin is applied on the accepted
      // socket, which is itself a BCSSLSocket, inside the server thread below.

      final int kemBefore = recorder.lookupsByType("KEM");
      final int kpgBefore = recorder.lookupsByType("KeyPairGenerator");
      final int kfBefore = recorder.lookupsByType("KeyFactory");

      final Future<Boolean> serverSide =
          executor.submit(
              () -> {
                try (SSLSocket s = (SSLSocket) srv.accept()) {
                  s.setSoTimeout(10_000);
                  ((BCSSLSocket) s).setParameters(bcParams);
                  s.startHandshake();
                  try (OutputStream os = s.getOutputStream();
                      InputStream is = s.getInputStream()) {
                    os.write(new byte[] {(byte) 0xAB});
                    os.flush();
                    int b = is.read();
                    return b == 0xCD;
                  }
                }
              });

      try (SSLSocket client =
          (SSLSocket)
              clientCtx.getSocketFactory().createSocket(srv.getInetAddress(), srv.getLocalPort())) {
        client.setSoTimeout(10_000);
        ((BCSSLSocket) client).setParameters(bcParams);
        client.startHandshake();
        assertEquals("TLSv1.3", client.getSession().getProtocol());

        try (InputStream is = client.getInputStream();
            OutputStream os = client.getOutputStream()) {
          int b = is.read();
          assertEquals(0xAB, b);
          os.write(new byte[] {(byte) 0xCD});
          os.flush();
        }
      }

      Boolean serverOk = serverSide.get(15, TimeUnit.SECONDS);
      assertTrue(serverOk, "server side handshake + echo should complete");

      if (expectAccpServesMlKem) {
        assertTrue(
            recorder.lookupsByType("KEM") > kemBefore
                || recorder.lookupsByType("KeyPairGenerator") > kpgBefore
                || recorder.lookupsByType("KeyFactory") > kfBefore,
            () ->
                "No ML-KEM lookups observed against the recording provider during the handshake. "
                    + "Total counters: "
                    + recorder.summary());
      }
      return true;
    } finally {
      executor.shutdownNow();
    }
  }

  private static X509Certificate buildSelfSignedCert(KeyPair kp) throws Exception {
    final X500Principal dn = new X500Principal("CN=accp-bcjsse-mlkem-test");
    final Date notBefore = new Date(System.currentTimeMillis() - 60_000L);
    final Date notAfter = new Date(System.currentTimeMillis() + 3_600_000L);
    final BigInteger serial = new BigInteger(64, new SecureRandom());
    final JcaX509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(dn, serial, notBefore, notAfter, dn, kp.getPublic());
    return new JcaX509CertificateConverter()
        .getCertificate(
            builder.build(
                new JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider("BC")
                    .build(kp.getPrivate())));
  }
}
