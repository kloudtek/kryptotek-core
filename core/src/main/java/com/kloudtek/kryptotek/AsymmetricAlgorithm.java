/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek;

import com.kloudtek.kryptotek.key.KeyPair;
import com.kloudtek.kryptotek.key.RSAKey;
import com.kloudtek.kryptotek.key.RSAKeyPair;


/**
 * Created by yannick on 09/11/13.
 */
public enum AsymmetricAlgorithm {
    RSA(RSAKeyPair.class, "RSA", "RSA/ECB/PKCS1PADDING");
    private final String jceId;
    private final String cryptAlg;
    private final Class<? extends KeyPair> keyPairClass;

    AsymmetricAlgorithm(Class<? extends KeyPair> keyPairClass) {
        this.keyPairClass = keyPairClass;
        jceId = name();
        cryptAlg = null;
    }

    AsymmetricAlgorithm(Class<? extends KeyPair> keyPairClass, String jceId, String cryptAlg) {
        this.keyPairClass = keyPairClass;
        this.jceId = jceId;
        this.cryptAlg = cryptAlg;
    }

    AsymmetricAlgorithm(Class<? extends KeyPair> keyPairClass, String jceId) {
        this.keyPairClass = keyPairClass;
        this.jceId = jceId != null ? jceId : name();
        cryptAlg = null;
    }

    public String getJceId() {
        return jceId;
    }

    public String getCryptAlg() {
        return cryptAlg;
    }

    public Class<? extends KeyPair> getKeyPairClass() {
        return keyPairClass;
    }
}
