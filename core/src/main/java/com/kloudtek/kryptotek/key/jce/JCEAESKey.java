/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.key.jce;

import com.kloudtek.kryptotek.EncodedKey;
import com.kloudtek.kryptotek.JCECryptoEngine;
import com.kloudtek.kryptotek.key.AESKey;

import javax.crypto.SecretKey;

import static com.kloudtek.kryptotek.CryptoAlgorithm.AES;

/**
 * Created by yannick on 18/12/2014.
 */
public class JCEAESKey extends JCESecretKey implements AESKey {
    public JCEAESKey(SecretKey secretKey) {
        super(Type.AES, secretKey, AES, true, true, false, false);
    }

    @Override
    public EncodedKey getEncoded() {
        return new EncodedKey(key.getEncoded(), EncodedKey.Format.RAW);
    }

    @Override
    public String getJceCryptAlgorithm(boolean compatibilityMode) {
        return JCECryptoEngine.AES_CBC_PKCS_5_PADDING;
    }
}
