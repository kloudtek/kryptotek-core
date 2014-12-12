/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.keystore;

import com.kloudtek.kryptotek.Key;

import java.security.InvalidKeyException;

/**
 * Created by yannick on 22/11/2014.
 */
public abstract class AbstractKeyStore implements KeyStore {
    @Override
    public Key getKey(String keyLabel) throws KeyNotFoundException, KeyStoreAccessException, InvalidKeyException {
        return getKey(keyLabel, null);
    }

    @Override
    public Key getKey(String keyLabel, KeyStoreAccessToken keyStoreAccessToken) throws KeyNotFoundException, KeyStoreAccessException, InvalidKeyException {
        return getKey(Key.class, keyLabel, keyStoreAccessToken);
    }

    @Override
    public void importKey(String label, Key key) throws KeyStoreAccessException {
        importKey(label, key, null);
    }
}
