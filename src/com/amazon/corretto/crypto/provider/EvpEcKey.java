// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.security.interfaces.ECKey;
import java.security.spec.ECParameterSpec;

abstract class EvpEcKey extends EvpKey implements ECKey {
    private static final long serialVersionUID = 1;

    protected volatile ECParameterSpec params;

    EvpEcKey(final InternalKey key, final boolean isPublicKey) {
        super(key, EvpKeyType.EC, isPublicKey);
    }

    @Override
    public ECParameterSpec getParams() {
        ECParameterSpec result = params;
        if (result == null) {
            synchronized (this) {
                result = params;
                if (result == null) {
                    result = nativeParams(ECParameterSpec.class);
                    params = result;
                }
            }
        }
        return result;
    }
}
