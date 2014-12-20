/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.key.jce;

import com.kloudtek.kryptotek.CryptoAlgorithm;

import java.security.KeyPair;

/**
 * Created by yannick on 18/12/2014.
 */
public abstract class JCEKeyPair extends AbstractJCEKey<KeyPair> implements JCEKey {
    public JCEKeyPair(KeyPair keyPair, Type keyType, CryptoAlgorithm algorithm, boolean encryptionKey, boolean decryptionKey, boolean signingKey, boolean signatureVerificationKey) {
        super(keyPair, keyType, algorithm, encryptionKey, decryptionKey, signingKey, signatureVerificationKey);
    }

    public KeyPair getKeyPair() {
        return key;
    }
}
