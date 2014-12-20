/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.key.jce;

import com.kloudtek.kryptotek.CryptoAlgorithm;

import java.security.PrivateKey;

/**
 * Created by yannick on 20/12/2014.
 */
public abstract class JCEPrivateKey extends AbstractJCEKey<PrivateKey> implements JCEKey {
    public JCEPrivateKey(PrivateKey privateKey, Type keyType, CryptoAlgorithm algorithm, boolean encryptionKey, boolean decryptionKey, boolean signingKey, boolean signatureVerificationKey) {
        super(privateKey, keyType, algorithm, encryptionKey, decryptionKey, signingKey, signatureVerificationKey);
    }

    public PrivateKey getPrivateKey() {
        return key;
    }
}
