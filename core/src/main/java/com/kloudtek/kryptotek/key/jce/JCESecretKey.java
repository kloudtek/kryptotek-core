/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.key.jce;

import com.kloudtek.kryptotek.CryptoAlgorithm;
import com.kloudtek.kryptotek.EncodedKey;
import com.kloudtek.kryptotek.InvalidKeyEncodingException;
import com.kloudtek.kryptotek.JCECryptoEngine;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;

/**
 * Created by yannick on 19/12/2014.
 */
public abstract class JCESecretKey extends AbstractJCEKey<SecretKey> implements JCEKey {
    public JCESecretKey(JCECryptoEngine cryptoEngine, SecretKey secretKey) {
        super(cryptoEngine, secretKey);
    }

    public JCESecretKey(JCECryptoEngine cryptoEngine, EncodedKey encodedKey) throws InvalidKeyException, InvalidKeyEncodingException {
        super(cryptoEngine, encodedKey);
    }

    public JCESecretKey(JCECryptoEngine cryptoEngine) {
        super(cryptoEngine);
    }

    public SecretKey getSecretKey() {
        return key;
    }

    @Override
    public String getJceCryptAlgorithm(boolean compatibilityMode) {
        return null;
    }
}
