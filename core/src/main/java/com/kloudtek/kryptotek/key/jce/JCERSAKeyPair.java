/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.key.jce;

import com.kloudtek.kryptotek.EncodedKey;
import com.kloudtek.kryptotek.JCECryptoEngine;
import com.kloudtek.kryptotek.key.RSAKeyPair;
import com.kloudtek.util.UnexpectedException;
import com.kloudtek.util.io.ByteArrayDataOutputStream;

import java.io.IOException;
import java.security.KeyPair;

import static com.kloudtek.kryptotek.CryptoAlgorithm.RSA;

/**
 * Created by yannick on 18/12/2014.
 */
public class JCERSAKeyPair extends JCEKeyPair implements RSAKeyPair {
    public JCERSAKeyPair(KeyPair keyPair) {
        super(keyPair, Type.RSA_KEYPAIR, RSA, true, true, true, true);
    }

    @Override
    public EncodedKey getEncoded() {
        try {
            ByteArrayDataOutputStream buf = new ByteArrayDataOutputStream();
            buf.writeData(key.getPrivate().getEncoded());
            buf.writeData(key.getPublic().getEncoded());
            return new EncodedKey(buf.toByteArray(), EncodedKey.Format.CUSTOM);
        } catch (IOException e) {
            throw new UnexpectedException(e);
        }
    }

    @Override
    public String getJceCryptAlgorithm(boolean compatibilityMode) {
        return JCECryptoEngine.getRSAEncryptionAlgorithm(compatibilityMode);
    }
}
