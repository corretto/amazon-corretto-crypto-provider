// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assumeMinimumVersion;
import static com.amazon.corretto.crypto.provider.test.TestUtil.versionCompare;
import static com.amazon.corretto.crypto.provider.test.TestUtil.NATIVE_PROVIDER;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;

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

import org.apache.commons.codec.binary.Hex;

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
            // Just use the default parameters
            List<Arguments> keys = new ArrayList<>();
            keys.add(Arguments.of(kpg.generateKeyPair(), algorithm));
            if (algorithm.equals("RSA")) {
                // Special case RSA with no CRT parameters
                KeyPair pair = kpg.generateKeyPair();
                RSAPrivateKey privKey = (RSAPrivateKey) pair.getPrivate();
                final KeyFactory jceFactory = KeyFactory.getInstance(algorithm);
                privKey = (RSAPrivateKey) jceFactory.generatePrivate(new RSAPrivateKeySpec(privKey.getModulus(), privKey.getPrivateExponent()));
                keys.add(Arguments.of(new KeyPair(pair.getPublic(), privKey), "RSA-NoCRT"));
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

    public static List<Arguments> dsaPairs() {
        return KEYPAIRS.get("DSA");
    }

    public static List<Arguments> ecPairs() {
        return KEYPAIRS.get("EC");
    }

    public static List<Arguments> dhPairs() {
        return KEYPAIRS.get("DH");
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
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("rsaPairs")
    public void rsaPublic(final KeyPair keyPair, final String testName) throws Exception {
        Samples<RSAPublicKey> keys = getSamples(keyPair, false);

        assertEquals(keys.jceSample.getModulus(), keys.nativeSample.getModulus(), "Modulus");
        assertEquals(keys.jceSample.getPublicExponent(), keys.nativeSample.getPublicExponent(), "Public Exponent");
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("rsaPairs")
    @SuppressWarnings("unchecked")
    public void rsaPrivate(final KeyPair keyPair, final String testName) throws Exception {
        Samples<RSAPrivateKey> keys = getSamples(keyPair, true);

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

    private static void assertParamEquals(DSAParams jceParams, DSAParams nativeParams) {
        assertEquals(jceParams.getG(), nativeParams.getG(), "G");
        assertEquals(jceParams.getP(), nativeParams.getP(), "P");
        assertEquals(jceParams.getQ(), nativeParams.getQ(), "Q");
    }
    
    @ParameterizedTest(name = "{1}")
    @MethodSource("dsaPairs")
    public void dsaPrivate(final KeyPair keyPair, final String testName) throws Exception {
        Samples<DSAPrivateKey> keys = getSamples(keyPair, true);

        assertEquals(keys.jceSample.getX(), keys.nativeSample.getX(), "X");
        assertParamEquals(keys.jceSample.getParams(), keys.nativeSample.getParams());
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("dsaPairs")
    public void dsaPublic(final KeyPair keyPair, final String testName) throws Exception {
        Samples<DSAPublicKey> keys = getSamples(keyPair, false);

        assertEquals(keys.jceSample.getY(), keys.nativeSample.getY(), "Y");
        assertParamEquals(keys.jceSample.getParams(), keys.nativeSample.getParams());        
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("dsaPairs")
    public void dsaPrivateKeySpec(final KeyPair keyPair, final String testName) throws Exception {
        Samples<DSAPrivateKeySpec> specs = getSamples(keyPair, DSAPrivateKeySpec.class, true);

        assertEquals(specs.jceSample.getG(), specs.jceSample.getG(), "G");
        assertEquals(specs.jceSample.getP(), specs.jceSample.getP(), "P");
        assertEquals(specs.jceSample.getQ(), specs.jceSample.getQ(), "Q");
        assertEquals(specs.jceSample.getX(), specs.jceSample.getX(), "X");
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("dsaPairs")
    public void dsaPublicKeySpec(final KeyPair keyPair, final String testName) throws Exception {
        Samples<DSAPublicKeySpec> specs = getSamples(keyPair, DSAPublicKeySpec.class, false);

        assertEquals(specs.jceSample.getG(), specs.jceSample.getG(), "G");
        assertEquals(specs.jceSample.getP(), specs.jceSample.getP(), "P");
        assertEquals(specs.jceSample.getQ(), specs.jceSample.getQ(), "Q");
        assertEquals(specs.jceSample.getY(), specs.jceSample.getY(), "Y");
    }

    private static void assertParamEquals(DHParameterSpec jceParams, DHParameterSpec nativeParams) {
        assertEquals(jceParams.getG(), nativeParams.getG(), "G");
        assertEquals(jceParams.getP(), nativeParams.getP(), "P");
        assertEquals(jceParams.getL(), nativeParams.getL(), "L");
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("dhPairs")
    public void dhPrivate(final KeyPair keyPair, final String testName) throws Exception {
        Samples<DHPrivateKey> keys = getSamples(keyPair, true);

        assertEquals(keys.jceSample.getX(), keys.nativeSample.getX(), "X");
        assertParamEquals(keys.jceSample.getParams(), keys.nativeSample.getParams());
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("dhPairs")
    public void dhPublic(final KeyPair keyPair, final String testName) throws Exception {
        Samples<DHPublicKey> keys = getSamples(keyPair, false);

        assertEquals(keys.jceSample.getY(), keys.nativeSample.getY(), "Y");
        assertParamEquals(keys.jceSample.getParams(), keys.nativeSample.getParams());        
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("dhPairs")
    public void dhPrivateKeySpec(final KeyPair keyPair, final String testName) throws Exception {
        Samples<DHPrivateKeySpec> samples = getSamples(keyPair, DHPrivateKeySpec.class, true);

        assertEquals(samples.jceSample.getG(), samples.jceSample.getG(), "G");
        assertEquals(samples.jceSample.getP(), samples.jceSample.getP(), "P");
        assertEquals(samples.jceSample.getX(), samples.jceSample.getX(), "X");
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("dhPairs")
    public void dhPublicKeySpec(final KeyPair keyPair, final String testName) throws Exception {
        Samples<DHPublicKeySpec> samples = getSamples(keyPair, DHPublicKeySpec.class, false);

        assertEquals(samples.jceSample.getG(), samples.jceSample.getG(), "G");
        assertEquals(samples.jceSample.getP(), samples.jceSample.getP(), "P");
        assertEquals(samples.jceSample.getY(), samples.jceSample.getY(), "Y");
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("ecPairs")
    public void ecPrivate(final KeyPair keyPair, final String testName) throws Exception {
        Samples<ECPrivateKey> keys = getSamples(keyPair, true);

        EcGenTest.assertECEquals("ecPrivate", keys.jceSample, keys.nativeSample);
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("ecPairs")
    public void ecPublic(final KeyPair keyPair, final String testName) throws Exception {
        Samples<ECPublicKey> keys = getSamples(keyPair, false);

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

    @SuppressWarnings("unchecked")
    private static <T extends Key, S extends KeySpec> Samples<T> getSamples(KeyPair pair, boolean isPrivate) throws GeneralSecurityException {
        final String algorithm = pair.getPublic().getAlgorithm();
        final KeyFactory nativeFactory = KeyFactory.getInstance(algorithm, NATIVE_PROVIDER);
        final KeyFactory jceFactory = KeyFactory.getInstance(algorithm);
        final T nativeSample;
        final T jceSample;
        if (isPrivate) {
            final PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pair.getPrivate().getEncoded());
            nativeSample = (T) nativeFactory.generatePrivate(spec);
            jceSample = (T) jceFactory.generatePrivate(spec);
        } else {
            final X509EncodedKeySpec spec = new X509EncodedKeySpec(pair.getPublic().getEncoded());
            nativeSample = (T) nativeFactory.generatePublic(spec);
            jceSample = (T) jceFactory.generatePublic(spec);
        }

        assertEquals(jceSample.getAlgorithm(), nativeSample.getAlgorithm(), "Algorithm");
        assertEquals(jceSample.getFormat(), nativeSample.getFormat(), "Format");
        assertArrayEquals(jceSample.getEncoded(), nativeSample.getEncoded(), "Encoded");
        return new Samples<T>(nativeSample, jceSample);
    }

    @SuppressWarnings("unchecked")
    private static <T extends KeySpec> Samples<T> getSamples(KeyPair pair, Class<T> specKlass,  boolean isPrivate) throws GeneralSecurityException {
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

        // We don't check this for RSAPrivateKeySpec because ACCP *does* act slightly differently from the other JCE providers.
        // Since RSAPrivateCrtKeySpec extends RSAPrivateKeySpec, we return it whenever possible, even when RSAPrivateKeySpec is requested.
        // By doing this we can preserve the CRT parameters through code which may not be aware of them and thus still have the higher
        // CRT performance after the key is regenerated from them.
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
