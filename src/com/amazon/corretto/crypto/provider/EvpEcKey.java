// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.security.interfaces.ECKey;
import java.security.spec.ECParameterSpec;

abstract class EvpEcKey extends EvpKey implements ECKey {
    private static final long serialVersionUID = 1;

    protected ECParameterSpec params;

    EvpEcKey(InternalKey key, boolean isPublicKey) {
        super(key, EvpKeyType.EC, isPublicKey);
    }
    
    @Override
    public ECParameterSpec getParams() {
        synchronized (this) {
            if (params == null) {
                params = nativeParams(ECParameterSpec.class);
            }
        }
        return params;
    }
}
