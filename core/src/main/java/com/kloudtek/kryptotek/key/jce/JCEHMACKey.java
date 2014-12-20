/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.key.jce;

import com.kloudtek.kryptotek.EncodedKey;
import com.kloudtek.kryptotek.key.HMACKey;

import javax.crypto.SecretKey;

import static com.kloudtek.kryptotek.CryptoAlgorithm.HMAC;

/**
 * Created by yannick on 18/12/2014.
 */
public class JCEHMACKey extends JCESecretKey implements HMACKey {
    public JCEHMACKey(Type type, SecretKey secretKey) {
        super(type, secretKey, HMAC, true, true, false, false);
    }

    @Override
    public EncodedKey getEncoded() {
        return new EncodedKey(key.getEncoded(), EncodedKey.Format.RAW);
    }
}
