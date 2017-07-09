/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.jce;

import com.kloudtek.kryptotek.EncodedKey;
import com.kloudtek.kryptotek.InvalidKeyEncodingException;
import com.kloudtek.kryptotek.key.RSAPublicKey;
import com.kloudtek.util.UnexpectedException;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by yannick on 20/12/2014.
 */
public abstract class JCEPublicKey extends AbstractJCEKey<PublicKey> implements RSAPublicKey {
    public JCEPublicKey() {
    }

    public JCEPublicKey(JCECryptoEngine cryptoEngine, PublicKey publicKey) {
        super(cryptoEngine, publicKey);
    }

    public JCEPublicKey(JCECryptoEngine cryptoEngine, EncodedKey encodedKey) throws InvalidKeyException, InvalidKeyEncodingException {
        super(cryptoEngine, encodedKey);
    }

    public PublicKey getJCEPublicKey() {
        return key;
    }

    protected void readX509Key( String algorithm, byte[] encodedKey) throws InvalidKeyException {
        try {
            KeyFactory kf = KeyFactory.getInstance(algorithm);
            key = kf.generatePublic(new X509EncodedKeySpec(encodedKey));
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedException(e);
        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException(e);
        }
    }
}
