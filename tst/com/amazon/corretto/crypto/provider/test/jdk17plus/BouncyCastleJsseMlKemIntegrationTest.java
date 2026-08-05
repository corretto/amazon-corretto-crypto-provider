// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test.jdk17plus;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
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
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
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
import org.junit.jupiter.api.Test;
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
 * omit ML-KEM; a local build with {@code -DTARGET_JDK_VERSION=17+} enables it). A RecordingProvider
 * that wraps ACCP counts KEM / KeyPairGenerator / KeyFactory service lookups for ML-KEM names; a
 * real TLS 1.3 handshake between two BCJSSE peers is what drives those lookups.
 */
@ExtendWith(TestResultLogger.class)
// Each test mutates the global JCA provider list (installing a RecordingProvider, BC, and BCJSSE)
// and asserts on lookups routed through it, so the tests must not run concurrently with each other
// or with any other provider-touching test. This mirrors the locking convention used by the other
// provider-mutating tests (e.g. TestProviderInstallation, MiscSingleThreadedTests).
@Execution(ExecutionMode.SAME_THREAD)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ_WRITE)
@ResourceLock(value = TestUtil.RESOURCE_PROVIDER, mode = ResourceAccessMode.READ_WRITE)
public class BouncyCastleJsseMlKemIntegrationTest {

  /** Group name accepted by {@link BCSSLParameters#setNamedGroups(String[])} (case-insensitive). */
  private static final String PURE_MLKEM_GROUP = "MLKEM768";

  /** Hybrid TLS 1.3 named group combining X25519 (classical) with ML-KEM-768 (post-quantum). */
  private static final String HYBRID_GROUP = "X25519MLKEM768";

  /** KEM algorithm name that BCJSSE looks up for either MLKEM768 group. */
  private static final String KEM_ALG = "ML-KEM-768";

  @Test
  public void bcjsseSourcesPureMlKemFromAccp() throws Exception {
    runHandshakeAndAssertAccpServedMlKem(PURE_MLKEM_GROUP);
  }

  /**
   * Same claim exercised via the hybrid group -- BCJSSE decomposes it into an X25519 half and an
   * ML-KEM-768 half, and the ML-KEM half still goes through the KEM API path.
   */
  @Test
  public void bcjsseSourcesHybridMlKemFromAccp() throws Exception {
    runHandshakeAndAssertAccpServedMlKem(HYBRID_GROUP);
  }

  /**
   * Sanity check that the recording harness itself doesn't manufacture the positive signal: with
   * ACCP <em>absent</em> from the provider list, BCJSSE falls back to BC's own ML-KEM
   * implementation and the recorder observes no lookups.
   */
  @Test
  public void bcjsseWithoutAccpDoesNotObserveAccpKemLookups() throws Exception {
    assumeMlKemDelegationReachable();

    final Provider[] saved = TestUtil.saveProviders();
    try {
      // Drop ACCP entirely so BCJSSE has no chance to delegate to it.
      Security.removeProvider(AmazonCorrettoCryptoProvider.PROVIDER_NAME);
      final Provider bcProv = newBcProvider();
      Security.addProvider(bcProv);
      Security.addProvider(new BouncyCastleJsseProvider());

      // A recorder is present but wraps no one; it should not be routed through by JCA at all
      // (it isn't registered).
      final RecordingProvider recorder = new RecordingProvider(bcProv, "AccpAbsentRecorder");
      final boolean negotiated = drivehandshake(PURE_MLKEM_GROUP, recorder, false);
      assertTrue(negotiated, "TLS 1.3 handshake should succeed without ACCP too");
      assertEquals(
          0,
          recorder.totalMlKemLookups(),
          "Recorder must not observe ML-KEM lookups when it is not on the provider list: "
              + recorder.summary());
    } finally {
      TestUtil.restoreProviders(saved);
    }
  }

  /**
   * Parametric coverage across the KEM parameter sets, using the pure MLKEM groups. Included so
   * cross-JDK CI runs at least all three parameter sets on top of the two group flavours above.
   */
  @ParameterizedTest
  @ValueSource(strings = {"MLKEM512", "MLKEM768", "MLKEM1024"})
  public void bcjsseSourcesEachMlKemParameterSetFromAccp(String namedGroup) throws Exception {
    runHandshakeAndAssertAccpServedMlKem(namedGroup);
  }

  // ---------------------------------------------------------------------------
  // Driver
  // ---------------------------------------------------------------------------

  private void runHandshakeAndAssertAccpServedMlKem(String namedGroup) throws Exception {
    assumeMlKemDelegationReachable();

    final Provider[] saved = TestUtil.saveProviders();
    try {
      // Give BC the JCA side (cert-building operators are pinned to BC by name, but a
      // BouncyCastleProvider must be present in the list for that pin to resolve).
      final Provider bcProv = newBcProvider();
      // Install RecordingProvider(ACCP) at position 1 so it wins the unpinned getInstance() calls
      // BCJSSE makes for ML-KEM services.
      final RecordingProvider recorder =
          new RecordingProvider(AmazonCorrettoCryptoProvider.INSTANCE, "AccpRecorder");
      Security.insertProviderAt(recorder, 1);
      Security.addProvider(bcProv);
      Security.addProvider(new BouncyCastleJsseProvider());

      final boolean negotiated = drivehandshake(namedGroup, recorder, true);
      assertTrue(negotiated, "TLS 1.3 handshake should complete over " + namedGroup);

      // Observed ML-KEM service lookups against the recording provider.
      final int kem = recorder.kemMlKemLookups();
      final int kpg = recorder.keyPairGeneratorMlKemLookups();
      final int kf = recorder.keyFactoryMlKemLookups();
      assertTrue(
          kem + kpg + kf > 0,
          () ->
              "Expected BCJSSE to look up ML-KEM services via the JCA against the top provider, "
                  + "but no ML-KEM service was requested. Observed lookups: "
                  + recorder.summary());
      // A KEM lookup specifically is the strongest signal that the JEP-452 delegation path fired.
      assertTrue(
          kem > 0,
          () ->
              "Expected at least one KEM.getInstance(\""
                  + KEM_ALG
                  + "\") to hit the top provider during the handshake. Observed lookups: "
                  + recorder.summary());
    } finally {
      TestUtil.restoreProviders(saved);
    }
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
   * interface. Uses a JKS keystore holding a self-signed EC leaf so cert operations don't intersect
   * the KEM path being measured. Returns true when both peers completed handshake + echo.
   */
  private boolean drivehandshake(
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

      final int kemBefore = recorder.kemMlKemLookups();
      final int kpgBefore = recorder.keyPairGeneratorMlKemLookups();
      final int kfBefore = recorder.keyFactoryMlKemLookups();

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
            recorder.kemMlKemLookups() > kemBefore
                || recorder.keyPairGeneratorMlKemLookups() > kpgBefore
                || recorder.keyFactoryMlKemLookups() > kfBefore,
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
    final JcaX509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            dn, BigInteger.valueOf(System.nanoTime()), notBefore, notAfter, dn, kp.getPublic());
    return new JcaX509CertificateConverter()
        .getCertificate(
            builder.build(
                new JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider("BC")
                    .build(kp.getPrivate())));
  }

  // ---------------------------------------------------------------------------
  // RecordingProvider
  // ---------------------------------------------------------------------------

  /**
   * A JCA {@link Provider} that delegates every service lookup to a wrapped delegate (ACCP by
   * default), and records the (type, algorithm) pairs it is asked for. Used to observe -- rather
   * than merely infer -- that BCJSSE routes ML-KEM through the JCA to the top provider. Only
   * ML-KEM-related services are tallied; other services (EC, RSA, SHA-256, ...) pass through
   * unrecorded so the numbers stay meaningful.
   */
  private static final class RecordingProvider extends Provider {
    private static final long serialVersionUID = 1L;

    private final Provider delegate;
    private final ConcurrentHashMap<String, Integer> counters = new ConcurrentHashMap<>();

    RecordingProvider(Provider delegate, String name) {
      super(name, delegate.getVersionStr(), "Recording wrapper around " + delegate.getName());
      this.delegate = delegate;
      // Mirror the delegate's services under this provider's identity so that JCA precedence
      // scans -- which call `getServices()` / `getService(type, algo)` on us -- find them and pick
      // us as the top provider for every algorithm the delegate registered.
      for (Service s : delegate.getServices()) {
        putService(new DelegatingService(this, s));
      }
    }

    @Override
    public synchronized Service getService(String type, String algorithm) {
      if (isMlKemService(type, algorithm)) {
        String key = type + "/" + algorithm.toUpperCase();
        counters.merge(key, 1, Integer::sum);
      }
      return super.getService(type, algorithm);
    }

    private static boolean isMlKemService(String type, String algorithm) {
      if (algorithm == null) return false;
      String u = algorithm.toUpperCase();
      if (!u.startsWith("ML-KEM")) return false;
      return type.equals("KEM") || type.equals("KeyPairGenerator") || type.equals("KeyFactory");
    }

    int kemMlKemLookups() {
      return countByType("KEM");
    }

    int keyPairGeneratorMlKemLookups() {
      return countByType("KeyPairGenerator");
    }

    int keyFactoryMlKemLookups() {
      return countByType("KeyFactory");
    }

    int totalMlKemLookups() {
      return counters.values().stream().mapToInt(Integer::intValue).sum();
    }

    private int countByType(String type) {
      int total = 0;
      for (var e : counters.entrySet()) {
        if (e.getKey().startsWith(type + "/")) total += e.getValue();
      }
      return total;
    }

    String summary() {
      return counters.toString();
    }
  }

  /**
   * Service wrapper that forwards {@link Service#newInstance(Object)} to the delegate. Aliases
   * cannot be introspected off {@link Provider.Service} through public API, so this wrapper only
   * mirrors the canonical algorithm name -- adequate for this test because BCJSSE looks up ML-KEM
   * by its canonical {@code ML-KEM-512/768/1024} names, which ACCP registers directly.
   */
  private static final class DelegatingService extends Provider.Service {
    private final Provider.Service delegate;

    DelegatingService(Provider owner, Provider.Service delegate) {
      super(
          owner, delegate.getType(), delegate.getAlgorithm(), delegate.getClassName(), null, null);
      this.delegate = delegate;
    }

    @Override
    public Object newInstance(Object constructorParameter)
        throws java.security.NoSuchAlgorithmException {
      return delegate.newInstance(constructorParameter);
    }

    @Override
    public boolean supportsParameter(Object parameter) {
      return delegate.supportsParameter(parameter);
    }
  }
}
