/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.key.jce;

import com.kloudtek.kryptotek.EncodedKey;
import com.kloudtek.kryptotek.InvalidKeyEncodingException;
import com.kloudtek.kryptotek.JCECryptoEngine;
import com.kloudtek.kryptotek.key.RSAPrivateKey;
import com.kloudtek.util.UnexpectedException;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * Created by yannick on 18/12/2014.
 */
public class JCERSAPrivateKey extends JCEPrivateKey implements JCERSAKey, RSAPrivateKey {
    public JCERSAPrivateKey(JCECryptoEngine cryptoEngine, PrivateKey privateKey) {
        super(cryptoEngine, privateKey);
    }

    public JCERSAPrivateKey(JCECryptoEngine cryptoEngine, EncodedKey encodedKey) throws InvalidKeyEncodingException, InvalidKeyException {
        super(cryptoEngine,encodedKey);
    }

    @Override
    public EncodedKey.Format getDefaultEncoding() {
        return EncodedKey.Format.PKCS8;
    }

    @Override
    public void setDefaultEncoded(byte[] encodedKey) throws InvalidKeyException {
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            key = kf.generatePrivate(new PKCS8EncodedKeySpec(encodedKey));
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedException(e);
        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException(e);
        }
    }

    @Override
    public byte[] getDefaultEncoded() {
        return key.getEncoded();
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
