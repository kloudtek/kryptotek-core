/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.key.jce;

import com.kloudtek.kryptotek.EncodedKey;
import com.kloudtek.kryptotek.InvalidKeyEncodingException;
import com.kloudtek.kryptotek.JCECryptoEngine;
import com.kloudtek.kryptotek.key.AESKey;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;

/**
 * Created by yannick on 18/12/2014.
 */
public class JCEAESKey extends JCESecretKey implements AESKey {
    public JCEAESKey(JCECryptoEngine cryptoEngine, SecretKey secretKey) {
        super(cryptoEngine, secretKey);
    }

    public JCEAESKey(JCECryptoEngine cryptoEngine, EncodedKey encodedKey) throws InvalidKeyException, InvalidKeyEncodingException {
        super(cryptoEngine,encodedKey);
    }

    public JCEAESKey(JCECryptoEngine cryptoEngine, byte[] rawEncodedKey) {
        super(cryptoEngine);
        setDefaultEncoded(rawEncodedKey);
    }

    @Override
    public EncodedKey.Format getDefaultEncoding() {
        return EncodedKey.Format.RAW;
    }

    @Override
    public void setDefaultEncoded(byte[] encodedKey) {
        new SecretKeySpec(encodedKey, "AES");
    }

    @Override
    public byte[] getDefaultEncoded() {
        return key.getEncoded();
    }

    @Override
    public String getJceCryptAlgorithm(boolean compatibilityMode) {
        return JCECryptoEngine.AES_CBC_PKCS_5_PADDING;
    }
}
