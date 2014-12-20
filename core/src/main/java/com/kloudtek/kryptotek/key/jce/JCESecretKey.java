/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.key.jce;

import com.kloudtek.kryptotek.CryptoAlgorithm;
import com.kloudtek.kryptotek.Key;

import javax.crypto.SecretKey;

/**
 * Created by yannick on 19/12/2014.
 */
public abstract class JCESecretKey extends AbstractJCEKey<SecretKey> implements JCEKey {
    public JCESecretKey(Key.Type type, SecretKey secretKey, CryptoAlgorithm algorithm, boolean encryptionKey, boolean decryptionKey, boolean signingKey, boolean signatureVerificationKey) {
        super(secretKey, type, algorithm, encryptionKey, decryptionKey, signingKey, signatureVerificationKey);
    }

    public SecretKey getSecretKey() {
        return key;
    }

    @Override
    public String getJceCryptAlgorithm(boolean compatibilityMode) {
        return null;
    }
}
