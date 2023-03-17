// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.io.IOException;
import java.lang.reflect.Method;
import java.security.InvalidParameterException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.AlgorithmParametersSpi;


public final class EcParameters extends AlgorithmParametersSpi {
    private EcUtils.ECInfo ecInfo;

    // A public constructor is required by AlgorithmParameters class.
    public EcParameters() {}

    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        if (paramSpec == null) {
            throw new InvalidParameterSpecException("paramSpec must not be null");
        }

        String name = null;
        if (paramSpec instanceof ECParameterSpec) {
            name = EcUtils.getNameBySpec((ECParameterSpec) paramSpec);
            // Earlier Java TLS implementations cache curve params by OID instead of human-readable "shortname".
            // Specifying the shortname where OID is expected results in TLS handshake failures due to the server
            // not being able to "find" the intended curve, tricking the server into believing it doesn't support any
            // of the curves stipulated by the client.
            //
            // https://github.com/corretto/corretto-8/blob/235873fd43e5b7aa556d011f436e65a99c10c20a/jdk/src/share/classes/sun/security/ssl/SupportedGroupsExtension.java#L585-L607
            // https://github.com/openjdk/jdk10u/blob/ef9178d7d8a4489640a31a1d0c88958724af5304/src/java.base/share/classes/sun/security/ssl/SupportedGroupsExtension.java#L188-L210
            if (Utils.getJavaVersion() < 11) {
                name = EcUtils.getOidFromName(name);
            }
        } else if (paramSpec instanceof ECGenParameterSpec) {
            name = ((ECGenParameterSpec) paramSpec).getName();
        } else if ("sun.security.util.ECKeySizeParameterSpec".equals(paramSpec.getClass().getName())) {
            // OpenJDK's JCE sometimes passes ECKeySizeParameterSpec when initializing EC AlgorithmParameters. We can
            // reference this class directly using instanceof up until Java 8, but in Java 9 it was moved to the
            // java.base module and only exported to other JDK-internal modules. To work around this, we use reflection
            // to get the key size and get the corresponding curve name from our own database. Future versions of java
            // may restrict reflective access to private modules, so this functionality may break.
            //
            // https://github.com/corretto/corretto-11/blob/14c02261590b4dc01284888a7a51d39ff581ac8d/src/java.base/share/classes/sun/security/util/ECParameters.java#L121
            // https://github.com/corretto/corretto-11/blob/14c02261590b4dc01284888a7a51d39ff581ac8d/src/java.base/share/classes/module-info.java#L301-L314
            try {
                Method getKeySize = paramSpec.getClass().getMethod("getKeySize");
                Integer keySize = Integer.class.cast(getKeySize.invoke(paramSpec));
                name = EcUtils.getNameByKeySize(keySize);
            } catch (ReflectiveOperationException e) {
                // pass, perhaps due to reflective access control restrictions. rely null check below to throw.
            }
        }

        if (name == null) {
            throw new InvalidParameterSpecException("Only ECParameterSpec and ECGenParameterSpec supported");
        }

        ecInfo = EcUtils.getSpecByName(name);
        if (ecInfo == null) {
            throw new InvalidParameterSpecException("Unknown curve: " + paramSpec);
        }
    }

    protected void engineInit(byte[] params) throws IOException {
        String name = null;
        try {
            name = EcUtils.getNameByEncoded(params);
        } catch (RuntimeCryptoException e) {
            // pass, handle via null check below
        }
        if (name == null) {
            throw new IOException("Only named EcParameters supported");
        }
        ecInfo = EcUtils.getSpecByName(name);
        if (ecInfo == null) {
            throw new IOException("Unknown named curve: " + name);
        }
    }

    protected void engineInit(byte[] params, String unused) throws IOException {
        engineInit(params);
    }

    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> spec)
            throws InvalidParameterSpecException {

        if (spec.isAssignableFrom(ECParameterSpec.class)) {
            return spec.cast(ecInfo.spec);
        }

        if (spec.isAssignableFrom(ECGenParameterSpec.class)) {
            return spec.cast(new ECGenParameterSpec(ecInfo.name));
        }

        throw new InvalidParameterSpecException("Only ECParameterSpec and ECGenParameterSpec supported");
    }

    protected byte[] engineGetEncoded() throws IOException {
        return ecInfo.encoded.clone();  // clone to avoid exposing static reference
    }

    protected byte[] engineGetEncoded(String encodingMethod) throws IOException {
        return engineGetEncoded();
    }

    protected String engineToString() {
        if (ecInfo == null) {
            return "Not initialized";
        }

        return ecInfo.name;
    }
}
