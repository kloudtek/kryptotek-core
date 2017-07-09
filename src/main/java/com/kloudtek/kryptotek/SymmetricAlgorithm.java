/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek;

import com.kloudtek.kryptotek.key.AESKey;
import com.kloudtek.kryptotek.key.SymmetricKey;

import static com.kloudtek.kryptotek.CryptoEngine.AES_CBC_PKCS_5_PADDING;

/**
 * Created by yannick on 09/11/13.
 */
public enum SymmetricAlgorithm {
    AES(AESKey.class, AES_CBC_PKCS_5_PADDING);
    private final String jceId;
    private final Class<? extends SymmetricKey> keyClass;
    private final String defaultCompatCipherAlg;
    private final String defaultCipherAlg;

    SymmetricAlgorithm(Class<? extends SymmetricKey> keyClass, String defaultCipherAlg) {
        this(keyClass, null, defaultCipherAlg, defaultCipherAlg);
    }

    SymmetricAlgorithm(Class<? extends SymmetricKey> keyClass, String jceId, String defaultCompatCipherAlg, String defaultCipherAlg) {
        this.keyClass = keyClass;
        this.defaultCompatCipherAlg = defaultCompatCipherAlg;
        this.defaultCipherAlg = defaultCipherAlg;
        this.jceId = jceId != null ? jceId : name();
    }

    public String getJceId() {
        return jceId;
    }

    public Class<? extends SymmetricKey> getKeyClass() {
        return keyClass;
    }

    public String getDefaultCompatCipherAlg() {
        return defaultCompatCipherAlg;
    }

    public String getDefaultCipherAlg() {
        return defaultCipherAlg;
    }

    public String getDefaultCipherAlg(boolean compatibilityMode) {
        return compatibilityMode ? defaultCompatCipherAlg : defaultCipherAlg;
    }
}
