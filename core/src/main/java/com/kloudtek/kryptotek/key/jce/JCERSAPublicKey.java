/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.key.jce;

import com.kloudtek.kryptotek.EncodedKey;
import com.kloudtek.kryptotek.JCECryptoEngine;

import java.security.PublicKey;

import static com.kloudtek.kryptotek.CryptoAlgorithm.RSA;

/**
 * Created by yannick on 18/12/2014.
 */
public class JCERSAPublicKey extends JCEPublicKey {
    public JCERSAPublicKey(PublicKey publicKey) {
        super(publicKey, Type.RSA_PUBLIC, RSA, true, false, true, false);
    }

    @Override
    public EncodedKey getEncoded() {
        return new EncodedKey(key.getEncoded(), EncodedKey.Format.X509);
    }

    @Override
    public String getJceCryptAlgorithm(boolean compatibilityMode) {
        return JCECryptoEngine.getRSAEncryptionAlgorithm(compatibilityMode);
    }
}
