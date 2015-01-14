/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.jce;

import com.kloudtek.kryptotek.EncodedKey;
import com.kloudtek.kryptotek.InvalidKeyEncodingException;
import org.jetbrains.annotations.NotNull;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;

/**
 * Created by yannick on 19/12/2014.
 */
public abstract class JCESecretKey extends AbstractJCEKey<SecretKey> implements JCEKey {
    public JCESecretKey() {
    }

    public JCESecretKey(JCECryptoEngine cryptoEngine, SecretKey secretKey) {
        super(cryptoEngine, secretKey);
    }

    public JCESecretKey(JCECryptoEngine cryptoEngine, EncodedKey encodedKey) throws InvalidKeyException, InvalidKeyEncodingException {
        super(cryptoEngine, encodedKey);
    }

    public JCESecretKey(JCECryptoEngine cryptoEngine) {
        super(cryptoEngine);
    }

    @NotNull
    public SecretKey getSecretKey() {
        return key;
    }

    @Override
    public String getJceCryptAlgorithm(boolean compatibilityMode) {
        return null;
    }
}
