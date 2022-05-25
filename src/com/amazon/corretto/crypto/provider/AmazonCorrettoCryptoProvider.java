// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

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


public final class AmazonCorrettoCryptoProvider extends java.security.Provider {
    private static final MethodHandles.Lookup LOOKUP = MethodHandles.lookup();

    private static final String PACKAGE_PREFIX = "com.amazon.corretto.crypto.provider.";
    private static final long serialVersionUID = 1L;

    public static final AmazonCorrettoCryptoProvider INSTANCE;
    public static final String PROVIDER_NAME = "AmazonCorrettoCryptoProvider";

    private final EnumSet<ExtraCheck> extraChecks = EnumSet.noneOf(ExtraCheck.class);
    private transient SelfTestSuite selfTestSuite = new SelfTestSuite();

    static {
        if (!Loader.IS_AVAILABLE && DebugFlag.VERBOSELOGS.isEnabled()) {
            getLogger("AmazonCorrettoCryptoProvider").fine("Native JCE libraries are unavailable - disabling");
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

        addService("KeyFactory", "RSA", "EvpKeyFactory$RSA");
        addService("KeyFactory", "EC", "EvpKeyFactory$EC");

        addService("KeyPairGenerator", "RSA", "RsaGen");
        addService("KeyPairGenerator", "EC", "EcGen");

        addService("Cipher", "RSA/ECB/NoPadding", "RsaCipher$NoPadding");
        addService("Cipher", "RSA/ECB/Pkcs1Padding", "RsaCipher$Pkcs1");
        addService("Cipher", "RSA/ECB/OAEPPadding", "RsaCipher$OAEP");
        addService("Cipher", "RSA/ECB/OAEPWithSHA-1AndMGF1Padding", "RsaCipher$OAEPSha1");

        for (String hash : new String[] { "MD5", "SHA1", "SHA256", "SHA384", "SHA512" }) {
            addService("Mac", "Hmac" + hash, "EvpHmac$" + hash);
        }

        addService("KeyAgreement", "ECDH", "EvpKeyAgreement$ECDH",
                   singletonMap("SupportedKeyClasses", "java.security.interfaces.ECPublicKey|java.security.interfaces.ECPrivateKey")
        );

        addService("SecureRandom", "LibCryptoRng", "LibCryptoRng$SPI",
                singletonMap("ThreadSafe", "true"), "DEFAULT")
                .setSelfTest(LibCryptoRng.SPI.SELF_TEST);

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

        addService("Signature", "NONEwithECDSA", "EvpSignatureRaw$NONEwithECDSA");
    }

    private ACCPService addService(final String type, final String algorithm, final String className) {
        return addService(type, algorithm, className, null);
    }

    private ACCPService addService(final String type, final String algorithm, final String className,
                                   Map<String, String> attributes, String... algorithmAliases
    ) {
        ACCPService service = new ACCPService(type, algorithm, className, asList(algorithmAliases), attributes);

        putService(service);

        return service;
    }

    private class ACCPService extends Service {
        private final MethodHandle ctor;
        private final MethodHandle algorithmSetter;

        // @GuardedBy("this") // Restore once replacement for JSR-305 available
        private boolean failMessagePrinted = false;
        private volatile boolean testsPassed = false;

        // Updated during initialization only
        private Supplier<SelfTestStatus> getTestStatus = selfTestSuite::runTests;

        public ACCPService(
                final String type, final String algorithm, final String className,
                final List<String> aliases,
                final Map<String, String> attributes
        ) {
            super(AmazonCorrettoCryptoProvider.this, type, algorithm, PACKAGE_PREFIX + className, aliases, attributes);

            try {
                Class<?> klass = AmazonCorrettoCryptoProvider.class.getClassLoader().loadClass(PACKAGE_PREFIX + className);
                MethodHandle tmpCtor;
                try {
                    tmpCtor = LOOKUP.findConstructor(klass, MethodType.methodType(void.class))
                        .asType(MethodType.methodType(Object.class));
                } catch (final NoSuchMethodException nsm) {
                    tmpCtor = LOOKUP.findConstructor(klass, MethodType.methodType(void.class, AmazonCorrettoCryptoProvider.class))
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

        @Override public Object newInstance(final Object constructorParameter) throws NoSuchAlgorithmException {
            if (constructorParameter != null) {
                // We do not currently support any algorithms that take ctor parameters.
                throw new NoSuchAlgorithmException("Constructor parameters not used with "
                                                           + getType() + "/" + getAlgorithm());
            }

            if (!testsPassed) {
                checkTests();
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
                            getLogger("AmazonCorrettoCryptoProvider").severe("Self tests failed - disabling. " +
                                                           "Detailed results: " + selfTestSuite.getAllTestResults()
                                                                                               .toString());
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

    // The superconstructor taking a double version is deprecated in java 9. However, the replacement for it is
    // unavailable in java 8, so to build on both with warnings on our only choice is suppress deprecation warnings.
    @SuppressWarnings({"deprecation"})
    public AmazonCorrettoCryptoProvider() {
        super("AmazonCorrettoCryptoProvider", PROVIDER_VERSION, "");

        Utils.optionsFromProperty(ExtraCheck.class, extraChecks, "extrachecks");

        if (!Loader.IS_AVAILABLE && DebugFlag.VERBOSELOGS.isEnabled()) {
            getLogger("AmazonCorrettoCryptoProvider").fine("Native JCE libraries are unavailable - disabling");

            // Don't implement anything
            return;
        }

        buildServiceMap();

        initializeSelfTests();
    }

    private synchronized void initializeSelfTests() {
        if (selfTestSuite == null) {
            selfTestSuite = new SelfTestSuite();
        }
        selfTestSuite.addSelfTest(EvpHmac.SHA512.SELF_TEST);
        selfTestSuite.addSelfTest(EvpHmac.SHA384.SELF_TEST);
        selfTestSuite.addSelfTest(EvpHmac.SHA256.SELF_TEST);
        selfTestSuite.addSelfTest(EvpHmac.SHA1.SELF_TEST);
        selfTestSuite.addSelfTest(EvpHmac.MD5.SELF_TEST);
        selfTestSuite.addSelfTest(LibCryptoRng.SPI.SELF_TEST);

        // Kick off self-tests in the background. It's vitally important that we don't actually _wait_ for these to
        // complete, as if we do we'll end up recursing through some JCE internals back to attempts to use
        // AmazonCorrettoCryptoProvider in some configurations.
        ForkJoinPool.commonPool().submit(selfTestSuite::runTests);
    }

    // Override annotation omitted so that it works/compiles in Java8
    public String getVersionStr() {
        return PROVIDER_VERSION_STR;
    }

    /**
     * Installs the AmazonCorrettoCryptoProvider provider as the highest-priority (i.e. default) provider systemwide.
     */
    public static void install() {
        Security.insertProviderAt(INSTANCE, 1);
    }

    /**
     * Queries (but does not run) all available self-test functionality and returns the result.
     * {@link SelfTestStatus#FAILED} will be returned if any tests have failed. Otherwise,
     * {@link SelfTestStatus#NOT_RUN} will be returned if any tests have not be run.
     * {@link SelfTestStatus#PASSED} will only be returned if all tests have been run and have
     * all passed.
     *
     * <p>Algorithms currently run by this method:
     * <ul>
     * <li>NIST800-90A/AES-CTR-256
     * <li>HMacSHA512
     * <li>HMacSHA384
     * <li>HMacSHA256
     * <li>HMacSHA1
     * <li>HMacMD5
     * </ul>
     *
     * @see #runSelfTests()
     */
    public SelfTestStatus getSelfTestStatus() {
        return selfTestSuite.getOverallStatus();
    }

    /**
     * Runs all available self-tests and returns the result.
     * Please see {@link #getSelfTestStatus()} for the algorithms tested and
     * the possible return values. (though this method will never return
     * {@link SelfTestStatus#NOT_RUN}).
     *
     * @see #getSelfTestStatus()
     */
    public SelfTestStatus runSelfTests() {
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
     * <p>Throws an instance of {@link RuntimeCryptoException} if this library is not currently
     * functional. Otherwise does nothing.
     *
     * <p>This library is considered healthy if {@link #getLoadingError()} returns {@code null}
     * and {@link #runSelfTests()} returns {@link SelfTestStatus#PASSED}.
     */
    public void assertHealthy() throws RuntimeCryptoException {
        if (Loader.LOADING_ERROR != null) {
            throw new RuntimeCryptoException("Unable to load native library", Loader.LOADING_ERROR);
        }
        selfTestSuite.assertAllTestsPassed();
    }

    /**
     * Returns {@code true} if and only if the underlying libcrypto library is a FIPS build.
     */
    public boolean isFips() {
        return Loader.FIPS_BUILD && Loader.FIPS_BUILD_NATIVE;
    }

    @Override public synchronized boolean equals(final Object o) {
        return this == o;
    }

    @Override public synchronized int hashCode() {
        return System.identityHashCode(this);
    }

    @Override public String toString() {
        return super.toString() + (isFips() ? " (FIPS)" : "");
    }

    public Set<ExtraCheck> getExtraChecks() {
      return Collections.unmodifiableSet(extraChecks);
    }

    public boolean hasExtraCheck(ExtraCheck mode) {
      return extraChecks.contains(mode);
    }

    public void addExtraChecks(ExtraCheck...checks) {
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
                default:
                    throw new AssertionError("Unsupported key type");
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

}

