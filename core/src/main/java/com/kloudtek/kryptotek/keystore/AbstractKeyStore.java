/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.keystore;

import com.kloudtek.kryptotek.DigestAlgorithm;
import com.kloudtek.kryptotek.Key;
import com.kloudtek.kryptotek.key.*;
import org.jetbrains.annotations.NotNull;

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
    public void importKey(String label, com.kloudtek.kryptotek.Key key) throws KeyStoreAccessException {
        importKey(label, key, null);
    }

    @NotNull
    public abstract RSAKeyPair generateRSAKeyPair(String keyLabel, int keySize) throws KeyStoreAccessException;

    @NotNull
    public abstract AESKey generateAESKey(String keyLabel, int keySize) throws KeyStoreAccessException;

    @NotNull
    public abstract AESKey generateAESKey(String keyLabel, int keySize, DHPrivateKey dhPrivateKey, DHPublicKey dhPublicKey) throws InvalidKeyException, KeyStoreAccessException;

    @NotNull
    public abstract AESKey generatePBEAESKey(String keyLabel, char[] credential, int iterations, byte[] salt, int keyLen) throws KeyStoreAccessException;

    @NotNull
    public abstract HMACKey generateHMACKey(String keyLabel, DigestAlgorithm digestAlgorithm) throws KeyStoreAccessException;

    @NotNull
    public abstract HMACKey generateHMACKey(String keyLabel, DigestAlgorithm digestAlgorithm, DHPrivateKey dhPrivateKey, DHPublicKey dhPublicKey) throws InvalidKeyException, KeyStoreAccessException;
}
