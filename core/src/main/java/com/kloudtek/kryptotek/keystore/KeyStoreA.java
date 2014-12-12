/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.keystore;

import com.kloudtek.kryptotek.Key;

import java.security.InvalidKeyException;

/**
 * Created by yannick on 22/11/2014.
 */
public interface KeyStoreA {
    KeyStoreAccessToken getAccessToken(KeyStoreCredential credential) throws CredentialInvalidException, KeyStoreAccessException;

    <X extends Key> Key getKey(Class<X> keyClass, String keyLabel, KeyStoreAccessToken keyStoreAccessToken) throws KeyNotFoundException, KeyStoreAccessException, InvalidKeyException;

    Key getKey(String keyLabel, KeyStoreAccessToken keyStoreAccessToken) throws KeyNotFoundException, KeyStoreAccessException, InvalidKeyException;

    Key getKey(String keyLabel) throws KeyNotFoundException, KeyStoreAccessException, InvalidKeyException;

    void importKey(String label, Key key, KeyStoreAccessToken keyStoreAccessToken) throws KeyStoreAccessException;

    void importKey(String label, Key key) throws KeyStoreAccessException;
}
