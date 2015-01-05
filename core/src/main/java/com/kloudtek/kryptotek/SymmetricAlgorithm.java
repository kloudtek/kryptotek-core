/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek;

import com.kloudtek.kryptotek.key.AESKey;
import com.kloudtek.kryptotek.key.SymmetricKey;

/**
 * Created by yannick on 09/11/13.
 */
public enum SymmetricAlgorithm {
    AES(AESKey.class);
    private final String jceId;
    private final Class<? extends SymmetricKey> keyClass;

    SymmetricAlgorithm(Class<? extends SymmetricKey> keyClass) {
        this.keyClass = keyClass;
        jceId = name();
    }

    SymmetricAlgorithm(Class<? extends SymmetricKey> keyClass,String jceId) {
        this.keyClass = keyClass;
        this.jceId = jceId != null ? jceId : name();
    }

    public String getJceId() {
        return jceId;
    }

    public Class<? extends SymmetricKey> getKeyClass() {
        return keyClass;
    }
}
