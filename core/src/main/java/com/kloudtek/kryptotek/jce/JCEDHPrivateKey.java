/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.jce;

import com.kloudtek.kryptotek.EncodedKey;
import com.kloudtek.kryptotek.InvalidKeyEncodingException;
import com.kloudtek.kryptotek.key.DHPrivateKey;
import com.kloudtek.kryptotek.key.KeyType;
import com.kloudtek.util.UnexpectedException;

import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * Created by yannick on 26/01/2015.
 */
public class JCEDHPrivateKey extends JCEPrivateKey implements DHPrivateKey {
    public JCEDHPrivateKey() {
    }

    public JCEDHPrivateKey(JCECryptoEngine cryptoEngine, PrivateKey privateKey) {
        super(cryptoEngine, privateKey);
    }

    public JCEDHPrivateKey(JCECryptoEngine cryptoEngine, EncodedKey encodedKey) throws InvalidKeyException, InvalidKeyEncodingException {
        super(cryptoEngine, encodedKey);
    }

    @Override
    public EncodedKey.Format getDefaultEncoding() {
        return EncodedKey.Format.PKCS8;
    }

    @Override
    public void setDefaultEncoded(byte[] encodedKey) throws InvalidKeyException {
        readPKCS8Key("DH",encodedKey);
    }

    @Override
    public KeyType getType() {
        return KeyType.DH_PRIVATE;
    }
}
