/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.key;

import com.kloudtek.kryptotek.CryptoEngine;
import com.kloudtek.kryptotek.EncodedKey;
import com.kloudtek.kryptotek.InvalidKeyEncodingException;
import com.kloudtek.kryptotek.Key;
import com.kloudtek.util.UnexpectedException;

/**
 * Created by yannick on 18/12/2014.
 */
public abstract class AbstractKey implements Key {
    private CryptoEngine cryptoEngine;

    protected AbstractKey(CryptoEngine cryptoEngine) {
        this.cryptoEngine = cryptoEngine;
    }

    @Override
    public byte[] serialize() {
        try {
            return getEncoded(EncodedKey.Format.SERIALIZED).getEncodedKey();
        } catch (InvalidKeyEncodingException e) {
            throw new UnexpectedException();
        }
    }

    @Override
    public CryptoEngine getCryptoEngine() {
        return null;
    }
}
