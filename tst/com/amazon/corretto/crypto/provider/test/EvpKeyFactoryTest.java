// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assumeMinimumVersion;
import static com.amazon.corretto.crypto.provider.test.TestUtil.NATIVE_PROVIDER;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertNotSame;

import java.io.ByteArrayOutputStream;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import com.amazon.corretto.crypto.provider.ExtraCheck;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * This not only tests {@code EvpKeyFactory} but implicitly also tests all of our key implementations as well.
 */
@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class EvpKeyFactoryTest {
    private static Set<String> ALGORITHMS = new HashSet<>();
    private static Map<String, List<Arguments>> KEYPAIRS = new HashMap<>();

    @BeforeAll
    public static void setupParameters() throws Exception {
        assumeMinimumVersion("2.0.0", NATIVE_PROVIDER);
        for (Provider.Service service : NATIVE_PROVIDER.getServices()) {
            if ("KeyFactory".equals(service.getType())) {
                ALGORITHMS.add(service.getAlgorithm());
            }
        }

        for (String algorithm : ALGORITHMS) {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm);
            List<Arguments> keys = new ArrayList<>();
            if (algorithm.equals("EC")) {
                // Different curves can excercise different areas of ASN.1/DER and so should all be tested.
                final int[] keySizes = {256, 384, 521};

                for (int size : keySizes) {
                    kpg.initialize(size);
                    keys.add(Arguments.of(kpg.generateKeyPair(), algorithm + "-" + size));
                }
            } else {
                // Just use the default parameters
                keys.add(Arguments.of(kpg.generateKeyPair(), algorithm));
                if (algorithm.equals("RSA")) {
                    // Special case RSA with no CRT parameters
                    KeyPair pair = kpg.generateKeyPair();
                    RSAPrivateKey privKey = (RSAPrivateKey) pair.getPrivate();
                    final KeyFactory jceFactory = KeyFactory.getInstance(algorithm);
                    privKey = (RSAPrivateKey) jceFactory.generatePrivate(new RSAPrivateKeySpec(privKey.getModulus(), privKey.getPrivateExponent()));
                    keys.add(Arguments.of(new KeyPair(pair.getPublic(), privKey), "RSA-NoCRT"));
                }
            }
            KEYPAIRS.put(algorithm, keys);
        }

    }

    public static List<Arguments> allPairs() {
        List<Arguments> result = new ArrayList<>();
        for (Map.Entry<String, List<Arguments>> e : KEYPAIRS.entrySet()) {
            result.addAll(e.getValue());
        }
        return result;
    }

    public static List<Arguments> rsaPairs() {
        return KEYPAIRS.get("RSA");
    }

    public static List<Arguments> ecPairs() {
        return KEYPAIRS.get("EC");
    }

    public static List<Arguments> badEcPublicKeys() throws Exception {
        List<Arguments> result = new ArrayList<>();
        for (Arguments base : ecPairs()) {
            KeyPair pair = (KeyPair) base.get()[0];
            ECPublicKey goodKey = (ECPublicKey) pair.getPublic();
            String name = (String) base.get()[1];
            result.add(Arguments.of(
                EvpKeyAgreementTest.buildKeyAtInfinity(goodKey), name + ": Infinity"
            ));
            result.add(Arguments.of(
                EvpKeyAgreementTest.buildKeyOffCurve(goodKey), name + ": OffCurve"
            ));
        }
        return result;
    }

    public static List<Arguments> rsaPairsTranslation() {
        final List<Arguments> result = new ArrayList<>();
        for (Arguments base : KEYPAIRS.get("RSA")) {
            result.add(Arguments.of(base.get()[0], base.get()[1], false));
            result.add(Arguments.of(base.get()[0], base.get()[1], true));
        }
        return result;
    }

    public static List<Arguments> ecPairsTranslation() {
        final List<Arguments> result = new ArrayList<>();
        for (Arguments base : KEYPAIRS.get("EC")) {
            result.add(Arguments.of(base.get()[0], base.get()[1], false));
            result.add(Arguments.of(base.get()[0], base.get()[1], true));
        }
        return result;
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("allPairs")
    public void testX509Encoding(final KeyPair keyPair, final String testName) throws Exception {
        final PublicKey pubKey = keyPair.getPublic();
        final String algorithm = pubKey.getAlgorithm();

        final KeyFactory nativeFactory = KeyFactory.getInstance(algorithm, NATIVE_PROVIDER);
        final KeyFactory jceFactory = KeyFactory.getInstance(algorithm);

        final X509EncodedKeySpec nativeSpec = nativeFactory.getKeySpec(pubKey, X509EncodedKeySpec.class);
        final X509EncodedKeySpec jceSpec = jceFactory.getKeySpec(pubKey, X509EncodedKeySpec.class);

        assertArrayEquals(jceSpec.getEncoded(), nativeSpec.getEncoded(), "X.509 encodings match");

        // Get a spec with extra data
        final byte[] validSpec = nativeSpec.getEncoded();
        assertThrows(InvalidKeySpecException.class, () -> nativeFactory.generatePublic(new X509EncodedKeySpec(Arrays.copyOf(validSpec, validSpec.length + 1))));
        // Get a spec which has been truncated
        assertThrows(InvalidKeySpecException.class, () -> nativeFactory.generatePublic(new X509EncodedKeySpec(Arrays.copyOf(validSpec, validSpec.length - 1))));
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("allPairs")
    public void testPKCS8Encoding(final KeyPair keyPair, final String testName) throws Exception {
        final PrivateKey privKey = keyPair.getPrivate();
        final String algorithm = privKey.getAlgorithm();

        final KeyFactory nativeFactory = KeyFactory.getInstance(algorithm, NATIVE_PROVIDER);
        final KeyFactory jceFactory = KeyFactory.getInstance(algorithm);

        final PKCS8EncodedKeySpec nativeSpec = nativeFactory.getKeySpec(privKey, PKCS8EncodedKeySpec.class);
        final PKCS8EncodedKeySpec jceSpec = jceFactory.getKeySpec(privKey, PKCS8EncodedKeySpec.class);

        assertArrayEquals(jceSpec.getEncoded(), nativeSpec.getEncoded(), "PKCS #8 encodings match");

        // Get a spec with extra data
        final byte[] validSpec = nativeSpec.getEncoded();
        assertThrows(InvalidKeySpecException.class, () -> nativeFactory.generatePrivate(new PKCS8EncodedKeySpec(Arrays.copyOf(validSpec, validSpec.length + 1))));
        // Get a spec which has been truncated
        assertThrows(InvalidKeySpecException.class, () -> nativeFactory.generatePrivate(new PKCS8EncodedKeySpec(Arrays.copyOf(validSpec, validSpec.length - 1))));
    }

    @ParameterizedTest(name = "{1}, Translate: {2}")
    @MethodSource("rsaPairsTranslation")
    public void rsaPublic(final KeyPair keyPair, final String testName, final boolean translate) throws Exception {
        Samples<RSAPublicKey> keys = getSamples(keyPair, false, translate);

        assertEquals(keys.jceSample.getModulus(), keys.nativeSample.getModulus(), "Modulus");
        assertEquals(keys.jceSample.getPublicExponent(), keys.nativeSample.getPublicExponent(), "Public Exponent");
    }

    @ParameterizedTest(name = "{1}, Translate: {2}")
    @MethodSource("rsaPairsTranslation")
    public void rsaPrivate(final KeyPair keyPair, final String testName, final boolean translate) throws Exception {
        Samples<RSAPrivateKey> keys = getSamples(keyPair, true, translate);

        assertEquals(keys.jceSample.getModulus(), keys.nativeSample.getModulus(), "Modulus");
        assertEquals(keys.jceSample.getPrivateExponent(), keys.nativeSample.getPrivateExponent(), "Private Exponent");
        if (keyPair.getPrivate() instanceof RSAPrivateCrtKey) {
            final RSAPrivateCrtKey jceSample = (RSAPrivateCrtKey) keys.jceSample;
            final RSAPrivateCrtKey nativeSample = (RSAPrivateCrtKey) keys.nativeSample;
            assertEquals(jceSample.getCrtCoefficient(), nativeSample.getCrtCoefficient(), "CRT Coefficient");
            assertEquals(jceSample.getPrimeExponentP(), nativeSample.getPrimeExponentP(), "Prime Exponent P");
            assertEquals(jceSample.getPrimeExponentQ(), nativeSample.getPrimeExponentQ(), "Prime Exponent Q");
            assertEquals(jceSample.getPrimeP(), nativeSample.getPrimeP(), "P");
            assertEquals(jceSample.getPrimeQ(), nativeSample.getPrimeQ(), "Q");
            assertEquals(jceSample.getPublicExponent(), nativeSample.getPublicExponent(), "Public Exponent");
        }
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("rsaPairs")
    public void rsaPublicKeySpec(final KeyPair keyPair, final String testName) throws Exception {
        Samples<RSAPublicKeySpec> specs = getSamples(keyPair, RSAPublicKeySpec.class, false);

        assertEquals(specs.jceSample.getModulus(), specs.nativeSample.getModulus(), "Modulus");
        assertEquals(specs.jceSample.getPublicExponent(), specs.nativeSample.getPublicExponent(), "Public Exponent");
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("rsaPairs")
    public void rsaPrivateKeySpec(final KeyPair keyPair, final String testName) throws Exception {
        Samples<RSAPrivateKeySpec> specs = getSamples(keyPair, RSAPrivateKeySpec.class, true);

        assertEquals(specs.jceSample.getModulus(), specs.nativeSample.getModulus(), "Modulus");
        assertEquals(specs.jceSample.getPrivateExponent(), specs.nativeSample.getPrivateExponent(), "Private Exponent");
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("rsaPairs")
    public void rsaPrivateCrtKeySpec(final KeyPair keyPair, final String testName) throws Exception {
        if (!(keyPair.getPrivate() instanceof RSAPrivateCrtKey)) {
            assertThrows(InvalidKeySpecException.class, () -> getSamples(keyPair, RSAPrivateCrtKeySpec.class, true));
            return;
        }

        Samples<RSAPrivateCrtKeySpec> specs = getSamples(keyPair, RSAPrivateCrtKeySpec.class, true);

        assertEquals(specs.jceSample.getModulus(), specs.nativeSample.getModulus(), "Modulus");
        assertEquals(specs.jceSample.getPrivateExponent(), specs.nativeSample.getPrivateExponent(), "Private Exponent");
        assertEquals(specs.jceSample.getCrtCoefficient(), specs.nativeSample.getCrtCoefficient(), "CRT Coefficient");
        assertEquals(specs.jceSample.getPrimeExponentP(), specs.nativeSample.getPrimeExponentP(), "Prime Exponent P");
        assertEquals(specs.jceSample.getPrimeExponentQ(), specs.nativeSample.getPrimeExponentQ(), "Prime Exponent Q");
        assertEquals(specs.jceSample.getPrimeP(), specs.nativeSample.getPrimeP(), "P");
        assertEquals(specs.jceSample.getPrimeQ(), specs.nativeSample.getPrimeQ(), "Q");
        assertEquals(specs.jceSample.getPublicExponent(), specs.nativeSample.getPublicExponent(), "Public Exponent");
    }

    @Test
    public void rsaPrefersCrtParams() throws Exception {
        // Since RSAPrivateCrtKeySpec extends RSAPrivateKeySpec, we should try to return it from getKeySpec whenever possible.
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        RSAPrivateCrtKey privCrtKey = (RSAPrivateCrtKey) gen.generateKeyPair().getPrivate();

        KeyFactory factory = KeyFactory.getInstance("RSA", NATIVE_PROVIDER);
        RSAPrivateKeySpec spec = factory.getKeySpec(privCrtKey, RSAPrivateKeySpec.class);
        assertTrue(spec instanceof RSAPrivateCrtKeySpec, "Did not prefer RSAPrivateCrtKeySpec");

        // Ensure we properly get a CRT key back
        RSAPrivateKey privKey = (RSAPrivateKey) factory.generatePrivate(spec);
        assertTrue(privKey instanceof RSAPrivateCrtKey, "Did not return RSAPrivateCrtKey");

        // Explicitly strip out the CRT parameters
        RSAPrivateKeySpec strippedSpec = new RSAPrivateKeySpec(spec.getModulus(), spec.getPrivateExponent());
        // If we get a CRT key back, something is really confused
        privKey = (RSAPrivateKey) factory.generatePrivate(strippedSpec);
        assertFalse(privKey instanceof RSAPrivateCrtKey, "Incorrectly returned an RSAPrivateCrtKey");

        // Finally, when we request an instance of RSAPrivateKeySpec we don't get an instance of RSAPrivateCrtKeySpec (because we cannot construct it)
        spec = factory.getKeySpec(privKey, RSAPrivateKeySpec.class);
        assertFalse(spec instanceof RSAPrivateCrtKeySpec, "Incorrectly returned RSAPrivateCrtKeySpec");
    }

    @ParameterizedTest(name = "{1}, Translate: {2}")
    @MethodSource("ecPairsTranslation")
    public void ecPrivate(final KeyPair keyPair, final String testName, final boolean translate) throws Exception {
        Samples<ECPrivateKey> keys = getSamples(keyPair, true, translate);

        EcGenTest.assertECEquals("ecPrivate", keys.jceSample, keys.nativeSample);
    }

    @ParameterizedTest(name = "{1}, Translate: {2}")
    @MethodSource("ecPairsTranslation")
    public void ecPublic(final KeyPair keyPair, final String testName, final boolean translate) throws Exception {
        Samples<ECPublicKey> keys = getSamples(keyPair, false, translate);

        EcGenTest.assertECEquals("ecPublic", keys.jceSample, keys.nativeSample);
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("ecPairs")
    public void ecPrivateKeySpec(final KeyPair keyPair, final String testName) throws Exception {
        Samples<ECPrivateKeySpec> samples = getSamples(keyPair, ECPrivateKeySpec.class, true);

        assertEquals(samples.jceSample.getS(), samples.nativeSample.getS(), "S");
        EcGenTest.assertECEquals("ecPrivateKeySpec", samples.jceSample.getParams(), samples.nativeSample.getParams());
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("ecPairs")
    public void ecPublicKeySpec(final KeyPair keyPair, final String testName) throws Exception {
        Samples<ECPublicKeySpec> samples = getSamples(keyPair, ECPublicKeySpec.class, false);

        assertEquals(samples.jceSample.getW(), samples.nativeSample.getW(), "W");
        EcGenTest.assertECEquals("ecPrivateKeySpec", samples.jceSample.getParams(), samples.nativeSample.getParams());
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("badEcPublicKeys")
    public void ecInvalidPublicKeyRejected(final ECPublicKey badKey, final String testName) throws Exception {
        final KeyFactory nativeFactory = KeyFactory.getInstance("EC", NATIVE_PROVIDER);

        // Cannot translate it
        assertThrows(InvalidKeyException.class, () -> nativeFactory.translateKey(badKey));
        // Cannot construct it from encoding
        assertThrows(InvalidKeySpecException.class, () -> nativeFactory.generatePublic(new X509EncodedKeySpec(badKey.getEncoded())));
    }

    @Test
    public void rsaWithBadCrt() throws GeneralSecurityException {
        Assumptions.assumeTrue(NATIVE_PROVIDER.hasExtraCheck(ExtraCheck.PRIVATE_KEY_CONSISTENCY));
        // Corrupt out the CRT factors
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair pair = kpg.generateKeyPair();

        // The default Java key factory doesn't check for consistency
        KeyFactory jceFactory = KeyFactory.getInstance("RSA");
        final RSAPrivateCrtKeySpec goodSpec = jceFactory.getKeySpec(pair.getPrivate(), RSAPrivateCrtKeySpec.class);
        final RSAPrivateCrtKeySpec badSpec = new RSAPrivateCrtKeySpec(goodSpec.getModulus(),
                goodSpec.getPublicExponent(), goodSpec.getPrivateExponent(), goodSpec.getPrimeP(),
                goodSpec.getPrimeQ(), goodSpec.getPrimeP(),
                goodSpec.getPrimeExponentQ().add(BigInteger.ONE),
                goodSpec.getCrtCoefficient());
        final PrivateKey privateKey = jceFactory.generatePrivate(badSpec);

        KeyFactory nativeFactory = KeyFactory.getInstance("RSA", NATIVE_PROVIDER);

        assertThrows(InvalidKeySpecException.class, () -> nativeFactory.generatePrivate(badSpec));
        assertThrows(InvalidKeyException.class, () -> nativeFactory.translateKey(privateKey));
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("allPairs")
    public void cannotSerializeKeys(final KeyPair pair, final String testName) throws Exception {
        final KeyFactory nativeFactory = KeyFactory.getInstance(pair.getPublic().getAlgorithm(), NATIVE_PROVIDER);
        final Key publicKey = nativeFactory.translateKey(pair.getPublic());
        final Key privateKey = nativeFactory.translateKey(pair.getPrivate());
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             ObjectOutputStream out = new ObjectOutputStream(baos)) {

            assertThrows(NotSerializableException.class, () -> out.writeObject(publicKey));
            assertThrows(NotSerializableException.class, () -> out.writeObject(privateKey));
        }
    }

    @SuppressWarnings("unchecked")
    private static <T extends Key> Samples<T> getSamples(
            final KeyPair pair, final boolean isPrivate, final boolean isTranslated) throws GeneralSecurityException {
        final String algorithm = pair.getPublic().getAlgorithm();
        final KeyFactory nativeFactory = KeyFactory.getInstance(algorithm, NATIVE_PROVIDER);
        final KeyFactory jceFactory = KeyFactory.getInstance(algorithm);
        final T nativeSample;
        final T secondNativeSample; // Used for somer equality tests.
        final T jceSample;
        if (isTranslated) {
            if (isPrivate) {
                nativeSample = (T) nativeFactory.translateKey(pair.getPrivate());
                secondNativeSample = (T) nativeFactory.translateKey(pair.getPrivate());
                jceSample = (T) jceFactory.translateKey(pair.getPrivate());
            } else {
                nativeSample = (T) nativeFactory.translateKey(pair.getPublic());
                secondNativeSample = (T) nativeFactory.translateKey(pair.getPublic());
                jceSample = (T) jceFactory.translateKey(pair.getPublic());
            }
            assertNotSame(nativeSample, jceSample);
            // Retranslation should leave it the same
            assertSame(nativeSample, nativeFactory.translateKey(nativeSample));
        } else {
            if (isPrivate) {
                final PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pair.getPrivate().getEncoded());
                nativeSample = (T) nativeFactory.generatePrivate(spec);
                secondNativeSample = (T) nativeFactory.generatePrivate(spec);
                jceSample = (T) jceFactory.generatePrivate(spec);
            } else {
                final X509EncodedKeySpec spec = new X509EncodedKeySpec(pair.getPublic().getEncoded());
                nativeSample = (T) nativeFactory.generatePublic(spec);
                secondNativeSample = (T) nativeFactory.generatePublic(spec);
                jceSample = (T) jceFactory.generatePublic(spec);
            }
        }
        // Check is done in both directions to ensure that regardless of who's equality code is run, it still passes.
        assertEquals(jceSample, nativeSample);
        assertEquals(nativeSample, jceSample);
        assertEquals(jceSample.getAlgorithm(), nativeSample.getAlgorithm(), "Algorithm");
        assertEquals(jceSample.getFormat(), nativeSample.getFormat(), "Format");
        assertArrayEquals(jceSample.getEncoded(), nativeSample.getEncoded(), "Encoded");
        // This next check is fragile since the JDK might change how it calculates hashcodes,
        // but we'll try to match it so that us being equal to them will imply equal hash codes.
        assertEquals(jceSample.hashCode(), nativeSample.hashCode());

        // We have special logic for equality checks within our own provider. Try to cover some of that
        assertEquals(nativeSample, nativeSample);
        assertEquals(nativeSample, secondNativeSample);
        assertEquals(nativeSample.hashCode(), secondNativeSample.hashCode());

        // Using getPublicKey() let's us acquire multiple EvpKeys which are backed by the same native resource
        // but are different Java objects. This is very useful for testing.
        try {
            final PublicKey pub1 = TestUtil.sneakyInvoke(nativeSample, "getPublicKey");
            final PublicKey pub2 = TestUtil.sneakyInvoke(nativeSample, "getPublicKey");

            assertNotSame(pub1, pub2, "We expect getPublicKey() to return distinct instances for testsing purposes");
            assertEquals(pub1, pub2);
            assertEquals(pub2, pub1);
            assertEquals(pub1.hashCode(), pub2.hashCode());

            if (nativeSample instanceof PublicKey) {
                assertEquals(nativeSample, pub1);
                assertEquals(nativeSample.hashCode(), pub1.hashCode());
            } else {
                assertNotEquals(nativeSample, pub1);
            }
        } catch (final NoSuchMethodException ex) {
            // This is how we indicate that getPublicKey() isn't there, so just skip these tests.
        } catch (final Throwable t) {
            throw new RuntimeException(t);
        }
        return new Samples<T>(nativeSample, jceSample);
    }

    private static <T extends KeySpec> Samples<T> getSamples(
            final KeyPair pair, final Class<T> specKlass, final boolean isPrivate) throws GeneralSecurityException {
        final String algorithm = pair.getPublic().getAlgorithm();
        final KeyFactory nativeFactory = KeyFactory.getInstance(algorithm, NATIVE_PROVIDER);
        final KeyFactory jceFactory = KeyFactory.getInstance(algorithm);

        final Key sourceKey = isPrivate ? pair.getPrivate() : pair.getPublic();
        final T nativeSample = nativeFactory.getKeySpec(sourceKey, specKlass);
        final T jceSample = jceFactory.getKeySpec(sourceKey, specKlass);

        // Re-encode them and ensure this works correctly
        final Key jceKey;
        final Key nativeKey;
        if (isPrivate) {
            jceKey = jceFactory.generatePrivate(nativeSample);
            nativeKey = nativeFactory.generatePrivate(jceSample);
        } else {
            jceKey = jceFactory.generatePublic(nativeSample);
            nativeKey = nativeFactory.generatePublic(jceSample);
        }

        assertEquals(jceKey.getAlgorithm(), nativeKey.getAlgorithm(), "Algorithm");
        assertEquals(jceKey.getFormat(), nativeKey.getFormat(), "Format");

        // We don't check this for RSAPrivateKeySpec
        // because ACCP *does* act slightly differently from the other JCE providers.
        // Since RSAPrivateCrtKeySpec extends RSAPrivateKeySpec, we return it whenever possible,
        // even when RSAPrivateKeySpec is requested.
        // By doing this we can preserve the CRT parameters through code which may not be aware of them
        // and thus still have the higher CRT performance after the key is regenerated from them.
        if (!RSAPrivateKeySpec.class.equals(specKlass)) {
            assertArrayEquals(jceKey.getEncoded(), nativeKey.getEncoded(), "Encoded");
        }
        return new Samples<T>(nativeSample, jceSample);
    }

    private static class Samples<T> {
        final T nativeSample;
        final T jceSample;

        Samples(T nativeSample, T jceSample) {
            this.nativeSample = nativeSample;
            this.jceSample = jceSample;
        }
    }
}
