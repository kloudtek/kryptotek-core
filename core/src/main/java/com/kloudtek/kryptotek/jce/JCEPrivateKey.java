/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.jce;

import com.kloudtek.kryptotek.EncodedKey;
import com.kloudtek.kryptotek.InvalidKeyEncodingException;
import com.kloudtek.kryptotek.key.PrivateKey;
import com.kloudtek.util.UnexpectedException;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * Created by yannick on 20/12/2014.
 */
public abstract class JCEPrivateKey extends AbstractJCEKey<java.security.PrivateKey> implements JCEKey, PrivateKey {
    public JCEPrivateKey() {
    }

    public JCEPrivateKey(JCECryptoEngine cryptoEngine, java.security.PrivateKey privateKey) {
        super(cryptoEngine, privateKey);
    }

    public JCEPrivateKey(JCECryptoEngine cryptoEngine, EncodedKey encodedKey) throws InvalidKeyException, InvalidKeyEncodingException {
        super(cryptoEngine, encodedKey);
    }

    public java.security.PrivateKey getJCEPrivateKey() {
        return key;
    }

    @Override
    public byte[] getDefaultEncoded() {
        return key.getEncoded();
    }

    protected void readPKCS8Key( String algorithm, byte[] encodedKey ) throws InvalidKeyException {
        try {
            KeyFactory kf = KeyFactory.getInstance(algorithm);
            key = kf.generatePrivate(new PKCS8EncodedKeySpec(encodedKey));
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedException(e);
        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException(e);
        }
    }
}
