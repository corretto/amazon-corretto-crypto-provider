// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.security.interfaces.DSAKey;
import java.security.interfaces.DSAParams;
import java.security.spec.DSAParameterSpec;

abstract class EvpDsaKey extends EvpKey implements DSAKey {
    private static final long serialVersionUID = 1;

    protected DSAParameterSpec params;

    EvpDsaKey(InternalKey key, boolean isPublicKey) {
        super(key, EvpKeyType.DSA, isPublicKey);
    }

    @Override
    public DSAParams getParams() {
        synchronized(this) {
            if (params == null) {
                params = nativeParams(DSAParameterSpec.class);
            }
        }
        return params;
    }
}
