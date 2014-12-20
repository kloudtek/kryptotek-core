/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.key;

import com.kloudtek.kryptotek.CryptoAlgorithm;
import com.kloudtek.kryptotek.Key;

/**
 * Created by yannick on 18/12/2014.
 */
public abstract class AbstractKey implements Key {
    private final Type type;
    private final CryptoAlgorithm algorithm;
    private final boolean encryptionKey;
    private final boolean decryptionKey;
    private final boolean signingKey;
    private final boolean signatureVerificationKey;

    protected AbstractKey(Type type, CryptoAlgorithm algorithm, boolean encryptionKey, boolean decryptionKey, boolean signingKey, boolean signatureVerificationKey) {
        this.type = type;
        this.algorithm = algorithm;
        this.encryptionKey = encryptionKey;
        this.decryptionKey = decryptionKey;
        this.signingKey = signingKey;
        this.signatureVerificationKey = signatureVerificationKey;
    }

    @Override
    public Type getType() {
        return type;
    }

    @Override
    public CryptoAlgorithm getAlgorithm() {
        return algorithm;
    }

    @Override
    public boolean isEncryptionKey() {
        return encryptionKey;
    }

    @Override
    public boolean isDecryptionKey() {
        return decryptionKey;
    }

    @Override
    public boolean isSigningKey() {
        return signingKey;
    }

    @Override
    public boolean isSignatureVerificationKey() {
        return signatureVerificationKey;
    }
}
