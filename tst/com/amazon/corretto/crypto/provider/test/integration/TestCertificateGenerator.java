// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test.integration;

import static com.amazon.corretto.crypto.provider.test.integration.HTTPSTestParameters.SIGNATURE_METHODS_TO_TEST;
import static com.amazon.corretto.crypto.provider.test.integration.HTTPSTestParameters.SUPER_SECURE_PASSWORD;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayDeque;
import java.util.Date;
import java.util.HashMap;
import java.util.concurrent.TimeUnit;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * This tool is used to generate the test_CA.jks and test_private_keys.jks files used in the LocalHTTPSIntegrationTest.
 * It simply generates a root CA, plus a series of intermediate-and-leaf certificate pairs, with the leaf cert
 * signatures having a specific size and signing algorithm.
 *
 * Note that we need to use intermediates, as with a single CA all certs directly chained off the root must use a
 * signing algorithm compatible with the root CA type. We interpose the intermediate cert to allow it to use whatever
 * signing algorithm is appropriate for the root, and give the intermediate a key type that is compatible with the
 * final desired signature algorithm.
 */
public class TestCertificateGenerator {
    private static final String ROOT_SIGNATURE_ALGO = "SHA512withECDSA";
    private static final String ROOT_KEY_TYPE = "EC";

    private HashMap<String, KeyPair> cachedKeys = new HashMap<>();
    private KeyStore privateKeyStore;

    public TestCertificateGenerator() throws Exception {
        privateKeyStore = KeyStore.getInstance("JKS");
        privateKeyStore.load(null, null);

    }

    private KeyPair loadOrGenerateKeyPair(String keyType, int keyBits) throws Exception {
        if (keyType.equals("ECDSA")) {
            keyType = "EC";
        }

        String cacheKey = String.format("%s.%d", keyType, keyBits);

        if (cachedKeys.containsKey(cacheKey)) {
            return cachedKeys.get(cacheKey);
        }

        System.out.println("Generating new key for " + keyType + "/" + keyBits);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyType);

        kpg.initialize(keyBits);
        KeyPair keyPair = kpg.generateKeyPair();

        cachedKeys.put(cacheKey, keyPair);

        return keyPair;
    }

    private void generateCertificate(
            String alias,
            String dn,
            String caAlias,
            String keyType,
            int keyBits,
            String signatureAlgo,
            GeneralNames sniNames,
            boolean isCA
    ) throws Exception {

        KeyPair keyPair;
        try {
            keyPair = loadOrGenerateKeyPair(keyType, keyBits);
        } catch (Throwable t) {
            t.printStackTrace();
            throw t;
        }

        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        Date startDate = new Date(System.currentTimeMillis() - TimeUnit.DAYS.toMillis(2));
        Date expiryDate = new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365 * 20));

        X500Principal subjectName = new X500Principal(dn);
        X500Principal issuer;
        PrivateKey issuerKey;
        ArrayDeque<Certificate> certChain = new ArrayDeque<>();

        if (caAlias == null) {
            issuer = subjectName;
            issuerKey = privateKey;
        } else {
            issuerKey = (PrivateKey)privateKeyStore.getKey(caAlias, SUPER_SECURE_PASSWORD);
            byte[] caCert = privateKeyStore.getCertificate(caAlias).getEncoded();

            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate rootCertificate
                    = (X509Certificate)certFactory.generateCertificate(new ByteArrayInputStream(caCert));

            issuer = rootCertificate.getSubjectX500Principal();
            for (Certificate c : privateKeyStore.getCertificateChain(caAlias)) {
                certChain.addLast(c);
            }
        }

        JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
            issuer,
            BigInteger.TEN,
            startDate,
            expiryDate,
            subjectName,
            publicKey);

        certificateBuilder.addExtension(Extension.basicConstraints, false, new BasicConstraints(isCA));
        if (sniNames != null) {
            certificateBuilder.addExtension(Extension.subjectAlternativeName, false, sniNames);
        }
        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgo).build(issuerKey);

        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(contentSigner));
        certChain.addFirst(cert);

        privateKeyStore.setKeyEntry(
                alias,
                privateKey,
                SUPER_SECURE_PASSWORD,
                certChain.toArray(new Certificate[0])
        );
    }

    private void generateHostCertificate(
            String hostname,
            String keyType,
            int keyBits,
            String signatureAlgo
    ) throws Exception {
        // First generate an intermediate CA with the appropriate key type. We need this because the root's key might
        // not be usable with the signature algorithm we have chosen
        String intermediateAlias = "intermediate-" + hostname;
        generateCertificate(intermediateAlias,
                            String.format("CN=intermediate-" + hostname),
                            "root",
                            keyType,
                            keyBits,
                            ROOT_SIGNATURE_ALGO,
                            null,
                            true
        );

        GeneralNames gn = new GeneralNames(
                new GeneralName[]{
                        new GeneralName(GeneralName.dNSName, hostname),
                        new GeneralName(GeneralName.iPAddress, "127.0.0.1")
                }
        );

        String dn = String.format("CN=%s,O=TEST CERTIFICATE FOR algo %s bits %d", hostname, signatureAlgo, keyBits);

        generateCertificate(hostname, dn, intermediateAlias, keyType, keyBits, signatureAlgo, gn, false);
    }

    private void generateRootCertificate() throws Exception {
        generateCertificate(
                "root",
                "CN=TEST ROOT CERT",
                null,
                ROOT_KEY_TYPE,
                521,
                ROOT_SIGNATURE_ALGO,
                null,
                true
        );
    }

    private void writePrivateKeys(String path) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(path)) {
            privateKeyStore.store(fos, SUPER_SECURE_PASSWORD);
        }
    }

    private void writeCAKeystore(String path) throws Exception {
        KeyStore caStore = KeyStore.getInstance("JKS");
        caStore.load(null, null);
        caStore.setCertificateEntry("root", privateKeyStore.getCertificate("root"));

        try (FileOutputStream fos = new FileOutputStream(path)) {
            caStore.store(fos, SUPER_SECURE_PASSWORD);
        }
    }

    public static void main(String[] args) throws Exception {
        AmazonCorrettoCryptoProvider.install();
        //Security.insertProviderAt(new BouncyCastleProvider(), 1);

        TestCertificateGenerator generator = new TestCertificateGenerator();
        generator.generateRootCertificate();

        for (String sigMethod : SIGNATURE_METHODS_TO_TEST) {
            for (int keyBits : HTTPSTestParameters.keySizesForSignatureMethod(sigMethod)) {
                generator.generateHostCertificate(
                        sigMethod + "." + keyBits,
                        HTTPSTestParameters.getKeyType(sigMethod),
                        keyBits,
                        sigMethod
                );
            }
        }

        generator.writePrivateKeys("test_private_keys.jks");
        generator.writeCAKeystore("test_CA.jks");
    }
}
