/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.keystore;

import com.kloudtek.kryptotek.CryptoEngine;
import com.kloudtek.kryptotek.Key;

import java.security.InvalidKeyException;
import java.util.HashMap;

/**
 * Created by yannick on 22/11/2014.
 */
public class KeyStoreMemoryImpl extends AbstractKeyStore {
    private CryptoEngine cryptoEngine;
    private HashMap<String, Key> keys = new HashMap<String, Key>();

    public KeyStoreMemoryImpl(CryptoEngine cryptoEngine) {
        this.cryptoEngine = cryptoEngine;
    }

    @Override
    public <X extends Key> X getKey(Class<X> keyClass, String keyLabel, KeyStoreAccessToken keyStoreAccessToken) throws KeyNotFoundException, KeyStoreAccessException, InvalidKeyException {
        Key key = keys.get(keyLabel);
        if (!keyClass.isInstance(key)) {
            throw new InvalidKeyException("Key not of type " + keyClass.getName() + " but instead of type " + key.getClass().getName());
        }
        return keyClass.cast(key);
    }

    @Override
    public void importKey(String label, Key key, KeyStoreAccessToken keyStoreAccessToken) throws KeyStoreAccessException {
        keys.put(label, key);
    }

    @Override
    public KeyStoreAccessToken getAccessToken(KeyStoreCredential credential) throws CredentialInvalidException, KeyStoreAccessException {
        return new KeyStoreAccessToken() {
            @Override
            public Long getExpiry() {
                return null;
            }
        };
    }
}
