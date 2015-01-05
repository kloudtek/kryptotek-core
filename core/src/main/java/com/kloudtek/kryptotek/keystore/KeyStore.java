/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.keystore;

import com.kloudtek.kryptotek.EncodedKey;
import com.kloudtek.kryptotek.Key;

import java.security.InvalidKeyException;

/**
 * Created by yannick on 22/11/2014.
 */
public interface KeyStore {
    KeyStoreAccessToken getAccessToken(KeyStoreCredential credential) throws CredentialInvalidException, KeyStoreAccessException;

    <X extends com.kloudtek.kryptotek.Key> com.kloudtek.kryptotek.Key getKey(Class<X> keyClass, String keyLabel, KeyStoreAccessToken keyStoreAccessToken) throws KeyNotFoundException, KeyStoreAccessException, InvalidKeyException;

    com.kloudtek.kryptotek.Key getKey(String keyLabel, KeyStoreAccessToken keyStoreAccessToken) throws KeyNotFoundException, KeyStoreAccessException, InvalidKeyException;

    com.kloudtek.kryptotek.Key getKey(String keyLabel) throws KeyNotFoundException, KeyStoreAccessException, InvalidKeyException;

    <X extends Key> void importKey(String label, EncodedKey encodedKey, Class<X> keyType, KeyStoreAccessToken keyStoreAccessToken) throws KeyStoreAccessException, InvalidKeyException;

    void importKey(String label, com.kloudtek.kryptotek.Key key, KeyStoreAccessToken keyStoreAccessToken) throws KeyStoreAccessException;

    void importKey(String label, com.kloudtek.kryptotek.Key key) throws KeyStoreAccessException;
}
