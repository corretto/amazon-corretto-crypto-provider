// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import static com.amazon.corretto.crypto.provider.AesCbcSpi.AES_CBC_ISO10126_PADDING_NAMES;
import static com.amazon.corretto.crypto.provider.AesCbcSpi.AES_CBC_PKCS7_PADDING_NAMES;
import static com.amazon.corretto.crypto.provider.ConcatenationKdfSpi.CKDF_WITH_HMAC_SHA256;
import static com.amazon.corretto.crypto.provider.ConcatenationKdfSpi.CKDF_WITH_HMAC_SHA512;
import static com.amazon.corretto.crypto.provider.ConcatenationKdfSpi.CKDF_WITH_SHA256;
import static com.amazon.corretto.crypto.provider.ConcatenationKdfSpi.CKDF_WITH_SHA384;
import static com.amazon.corretto.crypto.provider.ConcatenationKdfSpi.CKDF_WITH_SHA512;
import static com.amazon.corretto.crypto.provider.CounterKdfSpi.CTR_KDF_WITH_HMAC_SHA256;
import static com.amazon.corretto.crypto.provider.CounterKdfSpi.CTR_KDF_WITH_HMAC_SHA384;
import static com.amazon.corretto.crypto.provider.CounterKdfSpi.CTR_KDF_WITH_HMAC_SHA512;
import static com.amazon.corretto.crypto.provider.EvpHmac.HMAC_PREFIX;
import static com.amazon.corretto.crypto.provider.EvpHmac.WITH_PRECOMPUTED_KEY;
import static com.amazon.corretto.crypto.provider.HkdfSecretKeyFactorySpi.HKDF_WITH_SHA1;
import static com.amazon.corretto.crypto.provider.HkdfSecretKeyFactorySpi.HKDF_WITH_SHA256;
import static com.amazon.corretto.crypto.provider.HkdfSecretKeyFactorySpi.HKDF_WITH_SHA384;
import static com.amazon.corretto.crypto.provider.HkdfSecretKeyFactorySpi.HKDF_WITH_SHA512;
import static com.amazon.corretto.crypto.provider.Loader.AWS_LC_VERSION_STR;
import static com.amazon.corretto.crypto.provider.Loader.EXPERIMENTAL_FIPS_BUILD;
import static com.amazon.corretto.crypto.provider.Loader.FIPS_BUILD;
import static com.amazon.corretto.crypto.provider.Loader.PROVIDER_VERSION;
import static com.amazon.corretto.crypto.provider.Loader.PROVIDER_VERSION_STR;
import static java.lang.String.format;
import static java.util.Arrays.asList;
import static java.util.Collections.singletonMap;
import static java.util.logging.Logger.getLogger;

import java.io.IOException;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ForkJoinPool;
import java.util.function.Supplier;
import javax.crypto.CipherSpi;

public final class AmazonCorrettoCryptoProvider extends java.security.Provider {
  private static final MethodHandles.Lookup LOOKUP = MethodHandles.lookup();

  private static final String PACKAGE_PREFIX = "com.amazon.corretto.crypto.provider.";
  private static final String PROPERTY_CACHE_SELF_TEST_RESULTS = "cacheselftestresults";
  private static final String PROPERTY_REGISTER_EC_PARAMS = "registerEcParams";
  private static final String PROPERTY_REGISTER_SECURE_RANDOM = "registerSecureRandom";
  private static final String PROPERTY_REGISTER_ED_KEYFACTORY = "registerEdKeyFactory";

  private static final long serialVersionUID = 1L;

  public static final AmazonCorrettoCryptoProvider INSTANCE;
  public static final String PROVIDER_NAME = "AmazonCorrettoCryptoProvider";

  private final EnumSet<ExtraCheck> extraChecks = EnumSet.noneOf(ExtraCheck.class);

  private final boolean relyOnCachedSelfTestResults;
  private final boolean shouldRegisterEcParams;
  private final boolean shouldRegisterSecureRandom;
  private final boolean shouldRegisterEdKeyFactory;
  private final boolean shouldRegisterMLDSA;
  private final boolean shouldRegisterAesCfb;
  private final boolean shouldRegisterMLKEM;
  private final Utils.NativeContextReleaseStrategy nativeContextReleaseStrategy;

  private transient SelfTestSuite selfTestSuite = new SelfTestSuite();

  static {
    if (!Loader.IS_AVAILABLE && DebugFlag.VERBOSELOGS.isEnabled()) {
      getLogger(PROVIDER_NAME).fine("Native JCE libraries are unavailable - disabling");
    }
    INSTANCE = new AmazonCorrettoCryptoProvider();
  }

  private void buildServiceMap() {
    addService("MessageDigest", "SHA-512", "SHA512Spi");
    addService("MessageDigest", "SHA-384", "SHA384Spi");
    addService("MessageDigest", "SHA-256", "SHA256Spi");
    addService("MessageDigest", "SHA-1", "SHA1Spi");
    addService("MessageDigest", "MD5", "MD5Spi");

    addService("Cipher", "AES/GCM/NoPadding", "AesGcmSpi");
    addService("Cipher", "AES_128/GCM/NoPadding", "AesGcmSpi");
    addService("Cipher", "AES_256/GCM/NoPadding", "AesGcmSpi");

    addService(
        "Cipher", "AES/KWP/NoPadding", "AesKeyWrapPaddingSpi", /*attributes*/ null, "AesWrapPad");

    addService("KeyFactory", "RSA", "EvpKeyFactory$RSA");
    addService("KeyFactory", "EC", "EvpKeyFactory$EC");

    if (shouldRegisterMLDSA) {
      addService("KeyFactory", "ML-DSA", "EvpKeyFactory$MLDSA");
      addService("KeyFactory", "ML-DSA-44", "EvpKeyFactory$MLDSA");
      addService("KeyFactory", "ML-DSA-65", "EvpKeyFactory$MLDSA");
      addService("KeyFactory", "ML-DSA-87", "EvpKeyFactory$MLDSA");
    }

    if (shouldRegisterMLKEM) {
      addService("KeyFactory", "ML-KEM", "EvpKeyFactory$MLKEM");
      addService("KeyFactory", "ML-KEM-512", "EvpKeyFactory$MLKEM");
      addService("KeyFactory", "ML-KEM-768", "EvpKeyFactory$MLKEM");
      addService("KeyFactory", "ML-KEM-1024", "EvpKeyFactory$MLKEM");
    }

    // KeyFactories are used to convert key encodings to Java Key objects. ACCP's KeyFactory for
    // Ed25519 returns keys of type EvpEdPublicKey and EvpEdPrivateKey that do not implement
    // EdECKey interface. One should register the KeyFactories from ACCP if they only use the
    // output of the factories with ACCP's services.
    if (shouldRegisterEdKeyFactory) {
      addService("KeyFactory", "EdDSA", "EvpKeyFactory$EdDSA");
      addService("KeyFactory", "Ed25519", "EvpKeyFactory$EdDSA");
    }
    addService("KeyPairGenerator", "EdDSA", "EdGen");
    addService("KeyPairGenerator", "Ed25519", "EdGen");

    addService("KeyFactory", "XDH", "EvpKeyFactory$XDH");
    addService("KeyFactory", "X25519", "EvpKeyFactory$XDH");
    addService("KeyPairGenerator", "XDH", "XDHGen");
    addService("KeyPairGenerator", "X25519", "XDHGen");

    final String hkdfSpi = "HkdfSecretKeyFactorySpi";
    addService("SecretKeyFactory", HKDF_WITH_SHA1, hkdfSpi, false);
    addService("SecretKeyFactory", HKDF_WITH_SHA256, hkdfSpi, false);
    addService("SecretKeyFactory", HKDF_WITH_SHA384, hkdfSpi, false);
    addService("SecretKeyFactory", HKDF_WITH_SHA512, hkdfSpi, false);

    final String concatenationKdfSpi = "ConcatenationKdfSpi";
    addService("SecretKeyFactory", CKDF_WITH_SHA256, concatenationKdfSpi, false);
    addService("SecretKeyFactory", CKDF_WITH_SHA384, concatenationKdfSpi, false);
    addService("SecretKeyFactory", CKDF_WITH_SHA512, concatenationKdfSpi, false);
    addService("SecretKeyFactory", CKDF_WITH_HMAC_SHA256, concatenationKdfSpi, false);
    addService("SecretKeyFactory", CKDF_WITH_HMAC_SHA512, concatenationKdfSpi, false);

    final String counterKdfSpi = "CounterKdfSpi";
    addService("SecretKeyFactory", CTR_KDF_WITH_HMAC_SHA256, counterKdfSpi, false);
    addService("SecretKeyFactory", CTR_KDF_WITH_HMAC_SHA384, counterKdfSpi, false);
    addService("SecretKeyFactory", CTR_KDF_WITH_HMAC_SHA512, counterKdfSpi, false);

    addService("KeyPairGenerator", "RSA", "RsaGen");
    addService("KeyPairGenerator", "EC", "EcGen");

    if (shouldRegisterMLDSA) {
      addService("KeyPairGenerator", "ML-DSA", "MlDsaGen$MlDsaGen44");
      addService("KeyPairGenerator", "ML-DSA-44", "MlDsaGen$MlDsaGen44");
      addService("KeyPairGenerator", "ML-DSA-65", "MlDsaGen$MlDsaGen65");
      addService("KeyPairGenerator", "ML-DSA-87", "MlDsaGen$MlDsaGen87");
    }

    if (shouldRegisterMLKEM) {
      addService("KeyPairGenerator", "ML-KEM", "MlKemGen$MlKemGen768");
      addService("KeyPairGenerator", "ML-KEM-512", "MlKemGen$MlKemGen512");
      addService("KeyPairGenerator", "ML-KEM-768", "MlKemGen$MlKemGen768");
      addService("KeyPairGenerator", "ML-KEM-1024", "MlKemGen$MlKemGen1024");
    }

    if (shouldRegisterMLKEM) {
      addService("KEM", "ML-KEM", "MlKemSpi$MlKemSpi768");
      addService("KEM", "ML-KEM-512", "MlKemSpi$MlKemSpi512");
      addService("KEM", "ML-KEM-768", "MlKemSpi$MlKemSpi768");
      addService("KEM", "ML-KEM-1024", "MlKemSpi$MlKemSpi1024");
    }

    addService("KeyGenerator", "AES", "SecretKeyGenerator", false);

    addService("Cipher", "AES/XTS/NoPadding", "AesXtsSpi", false);

    if (shouldRegisterAesCfb) {
      addService(
          "Cipher",
          "AES/CFB",
          "AesCfbSpi",
          true,
          singletonMap("SupportedModes", "CFB"),
          "AES_128/CFB",
          "AES_256/CFB");
    }

    addService(
        "Cipher",
        "AES/CBC",
        "AesCbcSpi",
        false,
        singletonMap("SupportedModes", "CBC"),
        "AES_128/CBC",
        "AES_192/CBC",
        "AES_256/CBC");

    addService("Cipher", "RSA/ECB/NoPadding", "RsaCipher$NoPadding");
    addService("Cipher", "RSA/ECB/Pkcs1Padding", "RsaCipher$Pkcs1");
    addService("Cipher", "RSA/ECB/OAEPPadding", "RsaCipher$OAEP");
    addService("Cipher", "RSA/ECB/OAEPWithSHA-1AndMGF1Padding", "RsaCipher$OAEPSha1");
    addService("Cipher", "RSA/ECB/OAEPWithSHA1AndMGF1Padding", "RsaCipher$OAEPSha1");

    final String hmacWithPrecomputedKeyKeyFactorySpi = "HmacWithPrecomputedKeyKeyFactorySpi";
    for (String hash : new String[] {"MD5", "SHA1", "SHA256", "SHA384", "SHA512"}) {
      // Registration of regular Hmac
      addService("Mac", "Hmac" + hash, "EvpHmac$" + hash);
      // Registration of Hmac with precomputed keys
      addService(
          "Mac",
          HMAC_PREFIX + hash + WITH_PRECOMPUTED_KEY,
          "EvpHmac$" + hash + WITH_PRECOMPUTED_KEY);
      addService(
          "SecretKeyFactory",
          HMAC_PREFIX + hash + WITH_PRECOMPUTED_KEY,
          hmacWithPrecomputedKeyKeyFactorySpi,
          false);
    }

    addService(
        "KeyAgreement",
        "ECDH",
        "EvpKeyAgreement$ECDH",
        singletonMap(
            "SupportedKeyClasses",
            "java.security.interfaces.ECPublicKey|java.security.interfaces.ECPrivateKey"));

    if (shouldRegisterEcParams) {
      registerEcParams();
    }

    if (shouldRegisterSecureRandom) {
      addService(
              "SecureRandom",
              "LibCryptoRng",
              "LibCryptoRng$SPI",
              singletonMap("ThreadSafe", "true"),
              "DEFAULT")
          .setSelfTest(LibCryptoRng.SPI.SELF_TEST);

      // If we `setProperty("SecureRandom.DEFAULT ThreadSafe", "true")`, then
      // TestProviderInstallation::testProviderInstallation fails. The unique thing about this test
      // is that it does `new SecureRandom` immediately after installing ACCP and expects to be
      // backed by ACCP.
    }

    addSignatures();
  }

  private void addSignatures() {
    // Basic signature styles
    final List<String> bases = asList("RSA", "ECDSA");
    final List<String> hashes = asList("SHA1", "SHA224", "SHA256", "SHA384", "SHA512");

    for (final String base : bases) {
      for (final String hash : hashes) {
        final String algorithm = format("%swith%s", hash, base);
        final String className = format("EvpSignature$%s", algorithm);
        addService("Signature", algorithm, className);
        if (base.equals("ECDSA")) {
          addService("Signature", algorithm + EvpSignatureBase.P1363_FORMAT_SUFFIX, className);
        }
      }
    }

    addService("Signature", "RSASSA-PSS", "EvpSignature$RSASSA_PSS");
    addService("Signature", "NONEwithECDSA", "EvpSignatureRaw$NONEwithECDSA");
    addService("Signature", "EdDSA", "EvpSignatureRaw$Ed25519");
    addService("Signature", "Ed25519", "EvpSignatureRaw$Ed25519");
    addService("Signature", "Ed25519ph", "EvpSignature$Ed25519ph");

    if (shouldRegisterMLDSA) {
      addService("Signature", "ML-DSA", "EvpSignatureRaw$MLDSA");
      addService("Signature", "ML-DSA-ExtMu", "EvpSignatureRaw$MLDSAExtMu");
    }
  }

  private ACCPService addService(
      final String type, final String algorithm, final String className) {
    return addService(type, algorithm, className, true, null);
  }

  private ACCPService addService(
      final String type,
      final String algorithm,
      final String className,
      final boolean useReflection) {
    return addService(type, algorithm, className, useReflection, null);
  }

  private ACCPService addService(
      final String type,
      final String algorithm,
      final String className,
      Map<String, String> attributes,
      String... algorithmAliases) {
    return addService(type, algorithm, className, true, attributes, algorithmAliases);
  }

  private ACCPService addService(
      final String type,
      final String algorithm,
      final String className,
      final boolean useReflection,
      Map<String, String> attributes,
      String... algorithmAliases) {
    ACCPService service =
        new ACCPService(
            type, algorithm, className, useReflection, asList(algorithmAliases), attributes);

    putService(service);

    return service;
  }

  private class ACCPService extends Service {
    private final boolean useReflection;
    private final MethodHandle ctor;
    private final MethodHandle algorithmSetter;

    // @GuardedBy("this") // Restore once replacement for JSR-305 available
    private boolean failMessagePrinted = false;
    private volatile boolean testsPassed = false;

    // Updated during initialization only
    private Supplier<SelfTestStatus> getTestStatus = selfTestSuite::runTests;

    public ACCPService(
        final String type,
        final String algorithm,
        final String className,
        final boolean
            useReflection, // this flag determines if the instantiation of the service class is
        // supposed to be done via reflection or explicitly
        final List<String> aliases,
        final Map<String, String> attributes) {
      super(
          AmazonCorrettoCryptoProvider.this,
          type,
          algorithm,
          PACKAGE_PREFIX + className,
          aliases,
          attributes);

      this.useReflection = useReflection;

      if (!useReflection) {
        ctor = null;
        algorithmSetter = null;
        return;
      }

      try {
        Class<?> klass =
            AmazonCorrettoCryptoProvider.class
                .getClassLoader()
                .loadClass(PACKAGE_PREFIX + className);
        MethodHandle tmpCtor;
        try {
          tmpCtor =
              LOOKUP
                  .findConstructor(klass, MethodType.methodType(void.class))
                  .asType(MethodType.methodType(Object.class));
        } catch (final NoSuchMethodException nsm) {
          tmpCtor =
              LOOKUP
                  .findConstructor(
                      klass, MethodType.methodType(void.class, AmazonCorrettoCryptoProvider.class))
                  .asType(MethodType.methodType(Object.class, AmazonCorrettoCryptoProvider.class))
                  .bindTo(AmazonCorrettoCryptoProvider.this);
        }
        ctor = tmpCtor;

        MethodHandle tmpAlgSetter = null;
        final MethodType setterSignature = MethodType.methodType(void.class, String.class);
        try {
          tmpAlgSetter = LOOKUP.findVirtual(klass, "setAlgorithmName", setterSignature);
        } catch (final NoSuchMethodException ex) {
          if (type.equals("Signature")) {
            throw ex;
          }
          // Just ignore this
        }
        algorithmSetter = tmpAlgSetter;
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    }

    @Override
    public Object newInstance(final Object constructorParameter) throws NoSuchAlgorithmException {
      if (isFips() && isFipsSelfTestFailureSkipAbort() && !isFipsStatusOk()) {
        throw new FipsStatusException(
            "The provider is built in FIPS non-abort mode and its status is not Ok.");
      }

      if (constructorParameter != null) {
        // We do not currently support any algorithms that take ctor parameters.
        throw new NoSuchAlgorithmException(
            "Constructor parameters not used with " + getType() + "/" + getAlgorithm());
      }

      if (!testsPassed) {
        checkTests();
      }

      if (!useReflection) {
        final String type = getType();
        final String algo = getAlgorithm();

        if ("SecretKeyFactory".equalsIgnoreCase(type)) {
          final HkdfSecretKeyFactorySpi spi =
              HkdfSecretKeyFactorySpi.INSTANCES.get(
                  HkdfSecretKeyFactorySpi.getSpiFactoryForAlgName(algo));
          if (spi != null) {
            return spi;
          }

          final ConcatenationKdfSpi ckdfSpi =
              ConcatenationKdfSpi.INSTANCES.get(ConcatenationKdfSpi.getSpiFactoryForAlgName(algo));
          if (ckdfSpi != null) {
            return ckdfSpi;
          }

          final CounterKdfSpi cntrKdfSpi =
              CounterKdfSpi.INSTANCES.get(CounterKdfSpi.getSpiFactoryForAlgName(algo));
          if (cntrKdfSpi != null) {
            return cntrKdfSpi;
          }

          final HmacWithPrecomputedKeyKeyFactorySpi hmacWithPrecomputedKeySpi =
              HmacWithPrecomputedKeyKeyFactorySpi.INSTANCES.get(
                  HmacWithPrecomputedKeyKeyFactorySpi.getSpiFactoryForAlgName(algo));
          if (hmacWithPrecomputedKeySpi != null) {
            return hmacWithPrecomputedKeySpi;
          }
        }

        if ("KeyGenerator".equalsIgnoreCase(type) && "AES".equalsIgnoreCase(algo)) {
          return SecretKeyGenerator.createAesKeyGeneratorSpi();
        }

        if ("Cipher".equalsIgnoreCase(type)) {
          return getCipherSpiInstance(algo);
        }

        throw new NoSuchAlgorithmException(String.format("No service class for %s/%s", type, algo));
      }

      try {
        Object result = (Object) ctor.invokeExact();
        if (algorithmSetter != null) {
          algorithmSetter.invoke(result, getAlgorithm());
        }
        return result;
      } catch (RuntimeException | Error e) {
        throw e;
      } catch (Throwable t) {
        throw new NoSuchAlgorithmException("Unexpected error constructing algorithm", t);
      }
    }

    private CipherSpi getCipherSpiInstance(String algo) throws NoSuchAlgorithmException {
      final boolean saveContext =
          AmazonCorrettoCryptoProvider.this.nativeContextReleaseStrategy
              == Utils.NativeContextReleaseStrategy.LAZY;
      if ("AES/XTS/NoPadding".equalsIgnoreCase(algo)) {
        return new AesXtsSpi();
      }
      if (AES_CBC_PKCS7_PADDING_NAMES.contains(algo.toLowerCase())) {
        return new AesCbcSpi(AesCbcSpi.Padding.PKCS7, saveContext);
      }
      if (AES_CBC_ISO10126_PADDING_NAMES.contains(algo.toLowerCase())) {
        return new AesCbcSpi(AesCbcSpi.Padding.ISO10126, saveContext);
      }
      // Allow the padding scheme to be set later by defaulting to a no-padding Cipher.
      if (algo.toUpperCase().startsWith("AES/CBC")) {
        return new AesCbcSpi(AesCbcSpi.Padding.NONE, saveContext);
      }
      throw new NoSuchAlgorithmException(format("No service class for Cipher/%s", algo));
    }

    private void checkTests() throws NoSuchAlgorithmException {
      /* Oracle JDK has a bug in which it attempts to verify the signature on an installed provider using that
       * provider itself. This can result in recursive validations, which break due to recursing through a
       * single ConcurrentHashMap's computeIfAbsent operation. It also completely defeats the point of checking
       * the signature...
       *
       * As a workaround, we'll refuse to supply anything if we're inside JAR validation (which we detect by
       * walking the stack). This is expensive, but we stop doing it once the self tests complete.
       */
      if (inJarValidation()) {
        /*
         * As an exception, if we've been asked for our RNG, we'll allow the recursive invocation.
         * This is because SecureRandom instantiation does not trigger JCE JAR signature validation, and
         * SecureRandom instances tend to end up being static final fields, so we want to make sure we don't
         * end up falling back.
         */
        if (!getType().equals("SecureRandom")) {
          throw new NoSuchAlgorithmException("Can't use ACCP before JAR validation completes");
        }
      }

      SelfTestStatus status = getTestStatus.get();

      switch (status) {
        case RECURSIVELY_INVOKED:
          throw new NoSuchAlgorithmException("Algorithm unavailable until self tests complete");
        case FAILED:
          synchronized (this) {
            if (!failMessagePrinted) {
              getLogger(PROVIDER_NAME)
                  .severe(
                      "Self tests failed - disabling. "
                          + "Detailed results: "
                          + selfTestSuite.getAllTestResults().toString());
              failMessagePrinted = true;
            }
          }
          throw new NoSuchAlgorithmException("Self-tests failed");
        case NOT_RUN:
          throw new NoSuchAlgorithmException("Internal error: self tests not run");
        case PASSED:
          testsPassed = true;
          break;
      }
    }

    private boolean inJarValidation() {
      StackTraceElement[] elements = Thread.currentThread().getStackTrace();

      for (StackTraceElement element : elements) {
        if (element.getClassName().equals("javax.crypto.JarVerifier")) {
          return true;
        }
      }

      return false;
    }

    public void setSelfTest(final SelfTestSuite.SelfTest selfTest) {
      this.getTestStatus = () -> selfTest.runTest().getStatus();
    }
  }

  // For testing only
  private void resetAllSelfTests() {
    selfTestSuite.resetAllSelfTests();
  }

  // The super constructor taking a double version is deprecated in java 9. However, the alternate
  // constructor taking a string version is unavailable in java 8. So to build on both with
  // warnings on, our only choice is to suppress deprecation warnings.
  @SuppressWarnings({"deprecation"})
  public AmazonCorrettoCryptoProvider() {
    super(
        PROVIDER_NAME,
        PROVIDER_VERSION,
        String.format(
            "%s %s%s%s (%s)",
            PROVIDER_NAME,
            PROVIDER_VERSION_STR,
            FIPS_BUILD ? "+FIPS" : "",
            EXPERIMENTAL_FIPS_BUILD ? "+EXP" : "",
            AWS_LC_VERSION_STR));
    this.relyOnCachedSelfTestResults =
        Utils.getBooleanProperty(PROPERTY_CACHE_SELF_TEST_RESULTS, true);
    this.shouldRegisterEcParams = Utils.getBooleanProperty(PROPERTY_REGISTER_EC_PARAMS, false);

    this.shouldRegisterSecureRandom =
        Utils.getBooleanProperty(PROPERTY_REGISTER_SECURE_RANDOM, true);

    this.shouldRegisterEdKeyFactory =
        Utils.getBooleanProperty(PROPERTY_REGISTER_ED_KEYFACTORY, false);

    this.shouldRegisterMLDSA = (!isFips() || isExperimentalFips());

    this.shouldRegisterAesCfb = (!isFips() || isExperimentalFips());

    this.shouldRegisterMLKEM = (Utils.isMlKemSupported() && (!isFips() || isExperimentalFips()));
    this.nativeContextReleaseStrategy = Utils.getNativeContextReleaseStrategyProperty();

    Utils.optionsFromProperty(ExtraCheck.class, extraChecks, "extrachecks");

    if (!Loader.IS_AVAILABLE) {
      if (DebugFlag.VERBOSELOGS.isEnabled()) {
        getLogger(PROVIDER_NAME).fine("Native JCE libraries are unavailable - disabling");
      }

      // If Loading failed, do not register any algorithms
      return;
    }

    buildServiceMap();
    initializeSelfTests();
  }

  Utils.NativeContextReleaseStrategy getNativeContextReleaseStrategy() {
    return nativeContextReleaseStrategy;
  }

  private synchronized void initializeSelfTests() {
    if (selfTestSuite == null) {
      selfTestSuite = new SelfTestSuite();
    }
    if (!Loader.IS_AVAILABLE) {
      // We're not available, there are no tests to add.
      // Empty suites automatically fail.
      return;
    }

    // The order of adding determines the order of failure reporting and test execution. We do not
    // short circuit
    // the execution of tests when a test fails.
    selfTestSuite.addSelfTest(SelfTestSuite.AWS_LC_SELF_TESTS);
    selfTestSuite.addSelfTest(LibCryptoRng.SPI.SELF_TEST);
    selfTestSuite.addSelfTest(EvpHmac.SHA512.SELF_TEST);
    selfTestSuite.addSelfTest(EvpHmac.SHA384.SELF_TEST);
    selfTestSuite.addSelfTest(EvpHmac.SHA256.SELF_TEST);
    selfTestSuite.addSelfTest(EvpHmac.SHA1.SELF_TEST);
    selfTestSuite.addSelfTest(EvpHmac.MD5.SELF_TEST);

    // Kick off self-tests in the background. It's vitally important that we don't actually _wait_
    // for these to complete, as if we do we'll end up recursing through some JCE internals back to
    // attempts to use AmazonCorrettoCryptoProvider in some configurations.
    ForkJoinPool.commonPool().submit(selfTestSuite::runTests);
  }

  // Override annotation omitted so that it works/compiles in Java8
  public String getVersionStr() {
    return PROVIDER_VERSION_STR;
  }

  public String getAwsLcVersionStr() {
    return AWS_LC_VERSION_STR;
  }

  /**
   * Installs the AmazonCorrettoCryptoProvider provider as the highest-priority (i.e. default)
   * provider systemwide.
   */
  public static void install() {
    Security.insertProviderAt(INSTANCE, 1);
  }

  /**
   * Queries (but does not run) all available self-test functionality and returns the result. {@link
   * SelfTestStatus#FAILED} will be returned if any tests have failed. Otherwise, {@link
   * SelfTestStatus#NOT_RUN} will be returned if any tests have not be run. {@link
   * SelfTestStatus#PASSED} will only be returned if all tests have been run and have all passed.
   *
   * <p>Algorithms currently run by this method:
   *
   * <ul>
   *   <li>NIST800-90A/AES-CTR-256
   *   <li>HMacSHA512
   *   <li>HMacSHA384
   *   <li>HMacSHA256
   *   <li>HMacSHA1
   *   <li>HMacMD5
   * </ul>
   *
   * @see #runSelfTests()
   */
  public SelfTestStatus getSelfTestStatus() {
    return selfTestSuite.getOverallStatus();
  }

  /**
   * Runs all available self-tests and returns the result. Please see {@link #getSelfTestStatus()}
   * for the algorithms tested and the possible return values. (though this method will never return
   * {@link SelfTestStatus#NOT_RUN}). The result of running tests are cached, and the subsequent
   * calls would avoid re-running tests. To modify this behaviour, one can set the system property
   * <em>com.amazon.corretto.crypto.provider.cacheselftestresults=false</em> so that every call to
   * this method would result in re-running tests.
   *
   * @see #getSelfTestStatus()
   */
  public SelfTestStatus runSelfTests() {
    if (!relyOnCachedSelfTestResults) {
      resetAllSelfTests();
    }
    return selfTestSuite.runTests();
  }

  /**
   * Returns any {@link Throwable} thrown by {@link System#loadLibrary(String)} when trying to
   * initialize this library. Returns {@code null} if everything loaded successfully.
   */
  public Throwable getLoadingError() {
    return Loader.LOADING_ERROR;
  }

  /**
   * Throws an instance of {@link RuntimeCryptoException} if this library is not currently
   * functional. Otherwise does nothing.
   *
   * <p>This library is considered healthy if {@link #getLoadingError()} returns {@code null} and
   * {@link #runSelfTests()} returns {@link SelfTestStatus#PASSED}.
   */
  public void assertHealthy() throws RuntimeCryptoException {
    if (Loader.LOADING_ERROR != null) {
      throw new RuntimeCryptoException("Unable to load native library", Loader.LOADING_ERROR);
    }

    if (!relyOnCachedSelfTestResults) {
      resetAllSelfTests();
    }

    selfTestSuite.assertAllTestsPassed();
  }

  /** Returns {@code true} if and only if the underlying libcrypto library is a FIPS build */
  public boolean isFips() {
    return Loader.FIPS_BUILD;
  }

  private native boolean isFipsStatusOkInternal();

  /**
   * @return true if and only if the underlying libcrypto library's FIPS related checks pass
   */
  public boolean isFipsStatusOk() {
    if (!isFips() || !isFipsSelfTestFailureSkipAbort()) {
      throw new UnsupportedOperationException("ACCP not built with FIPS_SELF_TEST_SKIP_ABORT");
    }
    // For "FipsStatus", we only care about AWS-LC's self test status.
    SelfTestStatus status = SelfTestSuite.AWS_LC_SELF_TESTS.getCachedResult().getStatus();
    if (status == SelfTestStatus.NOT_RUN) {
      // If FIPS self tests haven't completed, give them a 3s timeout to complete.
      final long timeout = 3 * 1000;
      final long deadline = System.currentTimeMillis() + timeout;
      do {
        if (System.currentTimeMillis() > deadline) {
          throw new RuntimeCryptoException("FIPS self tests timed out");
        }
        try {
          Thread.sleep(1);
        } catch (Exception e) {
          throw new RuntimeCryptoException(e);
        }
        status = SelfTestSuite.AWS_LC_SELF_TESTS.getCachedResult().getStatus();
      } while (status == SelfTestStatus.NOT_RUN);
    }
    return isFipsStatusOkInternal();
  }

  private native List<String> getFipsSelfTestFailuresInternal();

  public List<String> getFipsSelfTestFailures() {
    if (!isFips() || !isFipsSelfTestFailureSkipAbort()) {
      throw new UnsupportedOperationException("ACCP not built with FIPS_SELF_TEST_SKIP_ABORT");
    }
    return getFipsSelfTestFailuresInternal();
  }

  /**
   * ACCP-FIPS uses the FIPS branches/releases of AWS-LC. Experimental FIPS mode is to allow
   * building ACCP and AWS-LC in FIPS mode using non-FIPS branches/release. This allows one to
   * experiment with features that are not in FIPS branches yet.
   *
   * <p>Returns {@code true} if and only if the underlying ACCP is built in experimental fips mode.
   */
  public boolean isExperimentalFips() {
    return Loader.EXPERIMENTAL_FIPS_BUILD;
  }

  public boolean isFipsSelfTestFailureSkipAbort() {
    return Loader.FIPS_SELF_TEST_SKIP_ABORT;
  }

  /**
   * Register ACCP's EC-flavored AlgorithmParameters implementation
   *
   * <p>Most use-cases can and should rely on JCE-provided EC AlgorithmParameters implementation as
   * it supports more curves, is more broadly compatible, and does not affect FIPS compliance
   * posture as the EC parameters wrapper class doesn't actually do any cryptography. Only use
   * ACCP's EC parameters class if you will only ever encounter NIST curves or are trying to use
   * ACCP as a stand-alone JCA provider.
   */
  public void registerEcParams() {
    addService("AlgorithmParameters", "EC", "EcParameters");
  }

  @Override
  public synchronized boolean equals(final Object o) {
    return this == o;
  }

  @Override
  public synchronized int hashCode() {
    return System.identityHashCode(this);
  }

  @Override
  public String toString() {
    return super.toString() + (isFips() ? " (FIPS)" : "");
  }

  public Set<ExtraCheck> getExtraChecks() {
    return Collections.unmodifiableSet(extraChecks);
  }

  public boolean hasExtraCheck(ExtraCheck mode) {
    return extraChecks.contains(mode);
  }

  public void addExtraChecks(ExtraCheck... checks) {
    extraChecks.addAll(Arrays.asList(checks));
  }

  private void readObject(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    readObjectNoData();
  }

  private void readObjectNoData() {
    initializeSelfTests();
  }

  // This next block of code is a micro-optimization around getting instances of KeyFactories.
  // It turns out the KeyFactory.getInstance(String, Provider) can be expensive
  // (primarily due to synchronization of Provider.getService).
  // The JDK tries to speed up the fast-path by remembering the last service retrieved
  // for a given Provider and returning it quickly if it is retrieved again.
  //
  // With the move to EVP keys many of our SPIs require an instance of KeyFactory that they can
  // use (primarily for translateKey). Since this means that retrieving a non-KeyFactory SPI
  // shortly thereafter results in retrieving a KeyFactory SPI, there is real churn in
  // Provider.getService which can massively slow-down performance.
  //
  // This method will do a lazy-init (to avoid circular dependencies) of KeyFactories
  // for ACCP use only. This way we only create one of each and do not touch the expensive
  // Provider.getService logic.
  private transient volatile KeyFactory rsaFactory;
  private transient volatile KeyFactory ecFactory;
  private transient volatile KeyFactory xdhFactory;
  private transient volatile KeyFactory edFactory;
  private transient volatile KeyFactory mlDsaFactory;
  private transient volatile KeyFactory kemFactory;

  KeyFactory getKeyFactory(EvpKeyType keyType) {
    try {
      switch (keyType) {
        case RSA:
          if (rsaFactory == null) {
            rsaFactory = KeyFactory.getInstance(keyType.jceName, this);
          }
          return rsaFactory;
        case EC:
          if (ecFactory == null) {
            ecFactory = KeyFactory.getInstance(keyType.jceName, this);
          }
          return ecFactory;
        case XDH:
          if (xdhFactory == null) {
            xdhFactory = KeyFactory.getInstance(keyType.jceName, this);
          }
          return xdhFactory;
        case EdDSA:
          if (edFactory == null) {
            edFactory = new EdKeyFactory(this);
          }
          return edFactory;
        case MLDSA:
          if (mlDsaFactory == null) {
            mlDsaFactory = KeyFactory.getInstance(keyType.jceName, this);
          }
          return mlDsaFactory;
        case MLKEM:
          if (kemFactory == null) {
            kemFactory = KeyFactory.getInstance(keyType.jceName, this);
          }
          return kemFactory;
        default:
          throw new AssertionError(String.format("Unsupported key type: %s", keyType.jceName));
      }
    } catch (final NoSuchAlgorithmException ex) {
      throw new AssertionError(ex);
    }
  }

  // This is just a convenience method to provide syntactic sugar to callers
  KeyFactory getKeyFactory(String keyType) {
    return getKeyFactory(EvpKeyType.valueOf(keyType));
  }

  // This is just a convenience method to provide syntactic sugar to callers
  EvpKey translateKey(Key key, EvpKeyType keyType) throws InvalidKeyException {
    if (key instanceof EvpKey) {
      return (EvpKey) key;
    } else {
      return (EvpKey) getKeyFactory(keyType).translateKey(key);
    }
  }

  // In case the user does not register Ed25519 KeyFactories by ACCP, we still need one to be used
  // internally.
  private static class EdKeyFactory extends KeyFactory {
    EdKeyFactory(final AmazonCorrettoCryptoProvider provider) {
      super(new EvpKeyFactory.EdDSA(provider), provider, "Ed25519");
    }
  }
}
