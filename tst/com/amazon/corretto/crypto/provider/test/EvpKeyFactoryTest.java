// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assumeMinimumVersion;
import static com.amazon.corretto.crypto.provider.test.TestUtil.versionCompare;
import static com.amazon.corretto.crypto.provider.test.TestUtil.NATIVE_PROVIDER;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.HashMap;
import java.util.HashSet;
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
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
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
import org.junit.jupiter.params.provider.MethodSource;

import org.apache.commons.codec.binary.Hex;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class EvpKeyFactoryTest {
    private static Set<String> ALGORITHMS = new HashSet<>();
    private static Map<String, KeyPair> KEYPAIRS = new HashMap<>();

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
            KEYPAIRS.put(algorithm, kpg.generateKeyPair());
        }
    }

    public static Set<String> algorithmNames() {
        return ALGORITHMS;
    }

    @ParameterizedTest
    @MethodSource("algorithmNames")
    public void testX509Encoding(final String algorithm) throws Exception {
        PublicKey pubKey = KEYPAIRS.get(algorithm).getPublic();

        final KeyFactory nativeFactory = KeyFactory.getInstance(algorithm, NATIVE_PROVIDER);
        final KeyFactory jceFactory = KeyFactory.getInstance(algorithm);

        final X509EncodedKeySpec nativeSpec = nativeFactory.getKeySpec(pubKey, X509EncodedKeySpec.class);
        final X509EncodedKeySpec jceSpec = jceFactory.getKeySpec(pubKey, X509EncodedKeySpec.class);

        assertArrayEquals(jceSpec.getEncoded(), nativeSpec.getEncoded(), "X.509 encodings match");
    }
    
    @ParameterizedTest
    @MethodSource("algorithmNames")
    public void testPKCS8Encoding(final String algorithm) throws Exception {
        PrivateKey privKey = KEYPAIRS.get(algorithm).getPrivate();

        final KeyFactory nativeFactory = KeyFactory.getInstance(algorithm, NATIVE_PROVIDER);
        final KeyFactory jceFactory = KeyFactory.getInstance(algorithm);

        final PKCS8EncodedKeySpec nativeSpec = nativeFactory.getKeySpec(privKey, PKCS8EncodedKeySpec.class);
        final PKCS8EncodedKeySpec jceSpec = jceFactory.getKeySpec(privKey, PKCS8EncodedKeySpec.class);

        assertArrayEquals(jceSpec.getEncoded(), nativeSpec.getEncoded(), "PKCS #8 encodings match");
    }

    @Test
    public void rsaPublic() throws Exception {
        Samples<RSAPublicKey> keys = getSamples("RSA", false);

        assertEquals(keys.jceSample.getModulus(), keys.nativeSample.getModulus(), "Modulus");
        assertEquals(keys.jceSample.getPublicExponent(), keys.nativeSample.getPublicExponent(), "Public Exponent");
    }

    @Test
    public void rsaPrivate() throws Exception {
        Samples<RSAPrivateCrtKey> keys = getSamples("RSA", true);

        assertEquals(keys.jceSample.getModulus(), keys.nativeSample.getModulus(), "Modulus");
        assertEquals(keys.jceSample.getPrivateExponent(), keys.nativeSample.getPrivateExponent(), "Private Exponent");
        assertEquals(keys.jceSample.getCrtCoefficient(), keys.nativeSample.getCrtCoefficient(), "CRT Coefficient");
        assertEquals(keys.jceSample.getPrimeExponentP(), keys.nativeSample.getPrimeExponentP(), "Prime Exponent P");
        assertEquals(keys.jceSample.getPrimeExponentQ(), keys.nativeSample.getPrimeExponentQ(), "Prime Exponent Q");
        assertEquals(keys.jceSample.getPrimeP(), keys.nativeSample.getPrimeP(), "P");
        assertEquals(keys.jceSample.getPrimeQ(), keys.nativeSample.getPrimeQ(), "Q");
        assertEquals(keys.jceSample.getPublicExponent(), keys.nativeSample.getPublicExponent(), "Public Exponent");
    }

    @Test
    public void rsaPublicKeySpec() throws Exception {
        Samples<RSAPublicKeySpec> specs = getSamples("RSA", RSAPublicKeySpec.class, false);

        assertEquals(specs.jceSample.getModulus(), specs.nativeSample.getModulus(), "Modulus");
        assertEquals(specs.jceSample.getPublicExponent(), specs.nativeSample.getPublicExponent(), "Public Exponent");
    }

    @Test
    public void rsaPrivateKeySpec() throws Exception {
        Samples<RSAPrivateKeySpec> specs = getSamples("RSA", RSAPrivateKeySpec.class, true);

        assertEquals(specs.jceSample.getModulus(), specs.nativeSample.getModulus(), "Modulus");
        assertEquals(specs.jceSample.getPrivateExponent(), specs.nativeSample.getPrivateExponent(), "Private Exponent");
    }

    @Test
    public void rsaPrivateCrtKeySpec() throws Exception {
        Samples<RSAPrivateCrtKeySpec> specs = getSamples("RSA", RSAPrivateCrtKeySpec.class, true);

        assertEquals(specs.jceSample.getModulus(), specs.nativeSample.getModulus(), "Modulus");
        assertEquals(specs.jceSample.getPrivateExponent(), specs.nativeSample.getPrivateExponent(), "Private Exponent");
        assertEquals(specs.jceSample.getCrtCoefficient(), specs.nativeSample.getCrtCoefficient(), "CRT Coefficient");
        assertEquals(specs.jceSample.getPrimeExponentP(), specs.nativeSample.getPrimeExponentP(), "Prime Exponent P");
        assertEquals(specs.jceSample.getPrimeExponentQ(), specs.nativeSample.getPrimeExponentQ(), "Prime Exponent Q");
        assertEquals(specs.jceSample.getPrimeP(), specs.nativeSample.getPrimeP(), "P");
        assertEquals(specs.jceSample.getPrimeQ(), specs.nativeSample.getPrimeQ(), "Q");
        assertEquals(specs.jceSample.getPublicExponent(), specs.nativeSample.getPublicExponent(), "Public Exponent");
    }

    private static void assertParamEquals(DSAParams jceParams, DSAParams nativeParams) {
        assertEquals(jceParams.getG(), nativeParams.getG(), "G");
        assertEquals(jceParams.getP(), nativeParams.getP(), "P");
        assertEquals(jceParams.getQ(), nativeParams.getQ(), "Q");
    }
    
    @Test
    public void dsaPrivate() throws Exception {
        Samples<DSAPrivateKey> keys = getSamples("DSA", true);

        assertEquals(keys.jceSample.getX(), keys.nativeSample.getX(), "X");
        assertParamEquals(keys.jceSample.getParams(), keys.nativeSample.getParams());
    }

    @Test
    public void dsaPublic() throws Exception {
        Samples<DSAPublicKey> keys = getSamples("DSA", false);

        assertEquals(keys.jceSample.getY(), keys.nativeSample.getY(), "Y");
        assertParamEquals(keys.jceSample.getParams(), keys.nativeSample.getParams());        
    }

    @Test
    public void dsaPrivateKeySpec() throws Exception {
        Samples<DSAPrivateKeySpec> specs = getSamples("DSA", DSAPrivateKeySpec.class, true);

        assertEquals(specs.jceSample.getG(), specs.jceSample.getG(), "G");
        assertEquals(specs.jceSample.getP(), specs.jceSample.getP(), "P");
        assertEquals(specs.jceSample.getQ(), specs.jceSample.getQ(), "Q");
        assertEquals(specs.jceSample.getX(), specs.jceSample.getX(), "X");
    }

    @Test
    public void dsaPublicKeySpec() throws Exception {
        Samples<DSAPublicKeySpec> specs = getSamples("DSA", DSAPublicKeySpec.class, false);

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

    @Test
    public void dhPrivate() throws Exception {
        Samples<DHPrivateKey> keys = getSamples("DH", true);

        assertEquals(keys.jceSample.getX(), keys.nativeSample.getX(), "X");
        assertParamEquals(keys.jceSample.getParams(), keys.nativeSample.getParams());
    }

    @Test
    public void dhPublic() throws Exception {
        Samples<DHPublicKey> keys = getSamples("DH", false);

        assertEquals(keys.jceSample.getY(), keys.nativeSample.getY(), "Y");
        assertParamEquals(keys.jceSample.getParams(), keys.nativeSample.getParams());        
    }

    @Test
    public void dhPrivateKeySpec() throws Exception {
        Samples<DHPrivateKeySpec> samples = getSamples("DH", DHPrivateKeySpec.class, true);

        assertEquals(samples.jceSample.getG(), samples.jceSample.getG(), "G");
        assertEquals(samples.jceSample.getP(), samples.jceSample.getP(), "P");
        assertEquals(samples.jceSample.getX(), samples.jceSample.getX(), "X");
    }

    @Test
    public void dhPublicKeySpec() throws Exception {
        Samples<DHPublicKeySpec> samples = getSamples("DH", DHPublicKeySpec.class, false);

        assertEquals(samples.jceSample.getG(), samples.jceSample.getG(), "G");
        assertEquals(samples.jceSample.getP(), samples.jceSample.getP(), "P");
        assertEquals(samples.jceSample.getY(), samples.jceSample.getY(), "Y");
    }

    @Test
    public void ecPrivate() throws Exception {
        Samples<ECPrivateKey> keys = getSamples("EC", true);

        EcGenTest.assertECEquals("ecPrivate", keys.jceSample, keys.nativeSample);
    }

    @Test
    public void ecPublic() throws Exception {
        Samples<ECPublicKey> keys = getSamples("EC", false);

        EcGenTest.assertECEquals("ecPublic", keys.jceSample, keys.nativeSample);
    }

    @Test
    public void ecPrivateKeySpec() throws Exception {
        Samples<ECPrivateKeySpec> samples = getSamples("EC", ECPrivateKeySpec.class, true);

        assertEquals(samples.jceSample.getS(), samples.nativeSample.getS(), "S");
        EcGenTest.assertECEquals("ecPrivateKeySpec", samples.jceSample.getParams(), samples.nativeSample.getParams());
    }

    @Test
    public void ecPublicKeySpec() throws Exception {
        Samples<ECPublicKeySpec> samples = getSamples("EC", ECPublicKeySpec.class, false);

        assertEquals(samples.jceSample.getW(), samples.nativeSample.getW(), "W");
        EcGenTest.assertECEquals("ecPrivateKeySpec", samples.jceSample.getParams(), samples.nativeSample.getParams());
    }

    @SuppressWarnings("unchecked")
    private static <T extends Key, S extends KeySpec> Samples<T> getSamples(final String algorithm, boolean isPrivate) throws GeneralSecurityException {
        final KeyPair pair = KEYPAIRS.get(algorithm);
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
    private static <T extends KeySpec> Samples<T> getSamples(final String algorithm, Class<T> specKlass,  boolean isPrivate) throws GeneralSecurityException {
        final KeyPair pair = KEYPAIRS.get(algorithm);
        final KeyFactory nativeFactory = KeyFactory.getInstance(algorithm, NATIVE_PROVIDER);
        final KeyFactory jceFactory = KeyFactory.getInstance(algorithm);

        final Key sourceKey = isPrivate ? pair.getPrivate() : pair.getPublic();
        final T nativeSample = nativeFactory.getKeySpec(sourceKey, specKlass);
        final T jceSample = jceFactory.getKeySpec(sourceKey, specKlass);

        // System.out.println("NativeSample: " + nativeSample);
        // System.out.println("jceSample: " + jceSample);
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

        // System.out.println("JCE Encoded: " + Hex.encodeHexString(jceKey.getEncoded()));
        // System.out.println("Native Encoded: " + Hex.encodeHexString(nativeKey.getEncoded()));
        assertArrayEquals(jceKey.getEncoded(), nativeKey.getEncoded(), "Encoded");
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
