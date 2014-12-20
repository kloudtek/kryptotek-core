/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.key.jce;

import com.kloudtek.kryptotek.EncodedKey;
import com.kloudtek.kryptotek.JCECryptoEngine;
import com.kloudtek.kryptotek.key.RSAPrivateKey;

import java.security.PrivateKey;

import static com.kloudtek.kryptotek.CryptoAlgorithm.RSA;

/**
 * Created by yannick on 18/12/2014.
 */
public class JCERSAPrivateKey extends JCEPrivateKey implements RSAPrivateKey {
    public JCERSAPrivateKey(PrivateKey privateKey) {
        super(privateKey, Type.RSA_PRIVATE, RSA, false, true, false, true);
    }

    @Override
    public EncodedKey getEncoded() {
        return new EncodedKey(key.getEncoded(), EncodedKey.Format.PKCS8);
    }

    @Override
    public String getJceCryptAlgorithm(boolean compatibilityMode) {
        return JCECryptoEngine.getRSAEncryptionAlgorithm(compatibilityMode);
    }
}
