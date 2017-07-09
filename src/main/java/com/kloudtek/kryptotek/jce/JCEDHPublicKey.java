/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.jce;

import com.kloudtek.kryptotek.EncodedKey;
import com.kloudtek.kryptotek.InvalidKeyEncodingException;
import com.kloudtek.kryptotek.key.DHPublicKey;
import com.kloudtek.kryptotek.key.KeyType;
import org.jetbrains.annotations.NotNull;

import java.security.InvalidKeyException;
import java.security.PublicKey;

/**
 * Created by yannick on 26/01/2015.
 */
public class JCEDHPublicKey extends JCEPublicKey implements DHPublicKey {
    public JCEDHPublicKey() {
    }

    public JCEDHPublicKey(@NotNull JCECryptoEngine cryptoEngine, PublicKey publicKey) {
        super(cryptoEngine, publicKey);
    }

    public JCEDHPublicKey(@NotNull JCECryptoEngine cryptoEngine, EncodedKey encodedKey) throws InvalidKeyException, InvalidKeyEncodingException {
        super(cryptoEngine, encodedKey);
    }

    @Override
    public EncodedKey.Format getDefaultEncoding() {
        return EncodedKey.Format.X509;
    }

    @Override
    public void setDefaultEncoded(byte[] encodedKey) throws InvalidKeyException {
        readX509Key("DH",encodedKey);
    }

    @Override
    public KeyType getType() {
        return KeyType.DH_PUBLIC;
    }
}
