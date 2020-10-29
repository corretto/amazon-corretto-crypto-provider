// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import javax.crypto.interfaces.DHKey;
import javax.crypto.spec.DHParameterSpec;


abstract class EvpDhKey extends EvpKey implements DHKey {
    private static final long serialVersionUID = 1;

    protected DHParameterSpec params;

    EvpDhKey(InternalKey key, boolean isPublicKey) {
        super(key, EvpKeyType.DH, isPublicKey);
    }

    @Override
    public DHParameterSpec getParams() {
        synchronized (this) {
            if (params == null) {
                params = nativeParams(DHParameterSpec.class);
            }
        }
        return params;
    }
}
