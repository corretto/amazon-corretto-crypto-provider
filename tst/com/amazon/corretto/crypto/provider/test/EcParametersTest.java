// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.NATIVE_PROVIDER;
import static com.amazon.corretto.crypto.provider.test.EcGenTest.assertECEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.RSAKeyGenParameterSpec;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledForJreRange;
import org.junit.jupiter.api.condition.JRE;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;
import org.junit.jupiter.params.provider.MethodSource;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class EcParametersTest {

    private static String[][] legacyCurveParams() {
        return TestUtil.LEGACY_CURVES;
    }

    @ParameterizedTest
    @EnabledForJreRange(min=JRE.JAVA_8, max=JRE.JAVA_14)
    @MethodSource("legacyCurveParams")
    public void legacyCurves(ArgumentsAccessor arguments) throws Exception {
        for (final Object name : arguments.toArray()) {
            testCurveParamsByName((String) name);
        }
    }

    private static String[][] knownCurveParams() {
        return TestUtil.KNOWN_CURVES;
    }

    @ParameterizedTest
    @MethodSource("knownCurveParams")
    public void knownCurves(ArgumentsAccessor arguments) throws Exception {
        for (final Object name : arguments.toArray()) {
            testCurveParamsByName((String) name);
        }
    }

    private void testCurveParamsByName(String name) throws Exception {
        ECGenParameterSpec genSpec = new ECGenParameterSpec(name);
        final KeyPairGenerator jceGen = KeyPairGenerator.getInstance("EC", "SunEC");;
        final KeyPairGenerator nativeGen = KeyPairGenerator.getInstance("EC", NATIVE_PROVIDER);;
        jceGen.initialize(genSpec);
        nativeGen.initialize(genSpec);
        KeyPair jcePair = jceGen.generateKeyPair();
        KeyPair nativePair = nativeGen.generateKeyPair();
        final ECParameterSpec jceParams = ((ECPublicKey) jcePair.getPublic()).getParams();
        final ECParameterSpec nativeParams = ((ECPublicKey) nativePair.getPublic()).getParams();
        assertECEquals(name, jceParams, nativeParams);

        // Ensure mutual compatibility between JCE and ACCP for conversion to/from ECParameterSpec
        final AlgorithmParameters jceAlgParams = AlgorithmParameters.getInstance("EC", "SunEC");
        final AlgorithmParameters nativeAlgParams = AlgorithmParameters.getInstance("EC", NATIVE_PROVIDER);
        jceAlgParams.init(jceParams);
        nativeAlgParams.init(nativeParams);
        final ECParameterSpec jceAlgSpec = jceAlgParams.getParameterSpec(ECParameterSpec.class);
        final ECParameterSpec nativeAlgSpec = nativeAlgParams.getParameterSpec(ECParameterSpec.class);
        assertECEquals(name, jceParams, jceAlgSpec);
        assertECEquals(name, nativeParams, nativeAlgSpec);
        assertECEquals(name, jceAlgSpec, nativeAlgSpec);
        assertNotNull(nativeAlgParams.toString());


        // Ensure mutual compatibility between JCE and ACCP for conversion to/from AlgorithmParameterSpec
        final AlgorithmParameters jceGenParams = AlgorithmParameters.getInstance("EC", "SunEC");
        final AlgorithmParameters nativeGenParams = AlgorithmParameters.getInstance("EC", NATIVE_PROVIDER);
        jceGenParams.init(genSpec);
        nativeGenParams.init(genSpec);
        final String jceCurveName = jceAlgParams.getParameterSpec(ECGenParameterSpec.class).getName();
        // Some versions of JCE will return the curve OID instead of curve name, so account for that
        // and convert ACCP's to corresponding OID before comparing.
        if (TestUtil.isOid(jceCurveName)) {
            final String nativeCurveOid = TestUtil.getCurveOid(
                nativeAlgParams.getParameterSpec(ECGenParameterSpec.class).getName()
            );
            assertEquals(jceCurveName, nativeCurveOid);
        } else {
            assertECEquals(
                name,
                jceAlgParams.getParameterSpec(ECGenParameterSpec.class),
                nativeAlgParams.getParameterSpec(ECGenParameterSpec.class)
            );
        }
        assertECEquals(name, genSpec, nativeGenParams.getParameterSpec(ECGenParameterSpec.class));

        // Ensure mutual compatibility between JCE and ACCP for encoding/decoding round trip
        byte[] jceEncodedParams = jceAlgParams.getEncoded();
        byte[] nativeEncodedParams = nativeAlgParams.getEncoded();
        assertArrayEquals(jceEncodedParams, nativeEncodedParams);
        AlgorithmParameters jceDecodedParams = AlgorithmParameters.getInstance("EC", "SunEC");
        AlgorithmParameters nativeDecodedParams = AlgorithmParameters.getInstance("EC", NATIVE_PROVIDER);
        jceDecodedParams.init(jceEncodedParams);
        nativeDecodedParams.init(nativeEncodedParams);
        ECParameterSpec jceDecodedSpec = jceDecodedParams.getParameterSpec(ECParameterSpec.class);
        ECParameterSpec nativeDecodedSpec = nativeDecodedParams.getParameterSpec(ECParameterSpec.class);
        assertECEquals(name, jceAlgSpec, jceDecodedSpec);
        assertECEquals(name, nativeAlgSpec, nativeDecodedSpec);
        assertECEquals(name, jceDecodedSpec, nativeDecodedSpec);

        // Included for coverage of ancillary method overloads
        nativeEncodedParams = nativeAlgParams.getEncoded("ignored encoding method");
        assertArrayEquals(nativeAlgParams.getEncoded(), nativeEncodedParams);
        nativeDecodedParams = AlgorithmParameters.getInstance("EC", NATIVE_PROVIDER);
        nativeDecodedParams.init(nativeEncodedParams, "ignored encoding method");
        nativeDecodedSpec = nativeDecodedParams.getParameterSpec(ECParameterSpec.class);
        assertECEquals(name, nativeAlgSpec, nativeDecodedSpec);
    }

    @Test
    public void testInitBadParams() throws Exception {
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC", NATIVE_PROVIDER);

        // AlgorithmParameters.init(AlgorithmParameterSpec)
        TestUtil.assertThrows(InvalidParameterSpecException.class, () -> params.init((ECParameterSpec) null));
        TestUtil.assertThrows(
            InvalidParameterSpecException.class,
            () -> params.init(new RSAKeyGenParameterSpec(0, BigInteger.ZERO))
        );
        TestUtil.assertThrows(  // invalid name/OID
            IllegalArgumentException.class,
            () -> params.init(new ECGenParameterSpec("lolNotACurve"))
        );
        TestUtil.assertThrows(  // valid OID for brainpoolP160r1, not on NIST standardization path
            IllegalArgumentException.class,
            () -> params.init(new ECGenParameterSpec("1.3.36.3.3.2.8.1.1.1"))
        );

        // AlgorithmParameters.init(byte[])
        TestUtil.assertThrows(IOException.class, () -> params.init((byte[]) null));
        TestUtil.assertThrows(IOException.class, () -> params.init(new byte[] {}));

        // AlgorithmParameters.init(byte[], String)
        TestUtil.assertThrows(IOException.class, () -> params.init((byte[]) null, "unused"));
    }
}
