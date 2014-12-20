/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.key.jce;

import com.kloudtek.kryptotek.CryptoAlgorithm;

import java.security.PublicKey;

/**
 * Created by yannick on 20/12/2014.
 */
public abstract class JCEPublicKey extends AbstractJCEKey<PublicKey> implements JCEKey {
    public JCEPublicKey(PublicKey publicKey, Type keyType, CryptoAlgorithm algorithm, boolean encryptionKey, boolean decryptionKey, boolean signingKey, boolean signatureVerificationKey) {
        super(publicKey, keyType, algorithm, encryptionKey, decryptionKey, signingKey, signatureVerificationKey);
    }

    public PublicKey getPublicKey() {
        return key;
    }
}
