/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.key.jce;

import com.kloudtek.kryptotek.EncodedKey;
import com.kloudtek.kryptotek.InvalidKeyEncodingException;
import com.kloudtek.kryptotek.JCECryptoEngine;
import com.kloudtek.kryptotek.key.RSAPublicKey;
import com.kloudtek.util.UnexpectedException;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by yannick on 18/12/2014.
 */
public class JCERSAPublicKey extends JCEPublicKey implements JCERSAKey, RSAPublicKey {
    public JCERSAPublicKey(JCECryptoEngine cryptoEngine, PublicKey publicKey) {
        super(cryptoEngine, publicKey);
    }

    public JCERSAPublicKey(JCECryptoEngine cryptoEngine, EncodedKey encodedKey) throws InvalidKeyException, InvalidKeyEncodingException {
        super(cryptoEngine, encodedKey);
    }

    @Override
    public EncodedKey getEncoded() {
        return new EncodedKey(key.getEncoded(), EncodedKey.Format.X509);
    }

    @Override
    public EncodedKey.Format getDefaultEncoding() {
        return EncodedKey.Format.X509;
    }

    @Override
    public void setDefaultEncoded(byte[] encodedKey) throws InvalidKeyException {
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            key = kf.generatePublic(new X509EncodedKeySpec(encodedKey));
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
    public String getJceCryptAlgorithm(boolean compatibilityMode) {
        return JCECryptoEngine.getRSAEncryptionAlgorithm(compatibilityMode);
    }
}
