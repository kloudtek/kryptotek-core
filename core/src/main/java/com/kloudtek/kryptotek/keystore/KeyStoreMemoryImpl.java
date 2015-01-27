/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.keystore;

import com.kloudtek.kryptotek.CryptoEngine;
import com.kloudtek.kryptotek.DigestAlgorithm;
import com.kloudtek.kryptotek.EncodedKey;
import com.kloudtek.kryptotek.Key;
import com.kloudtek.kryptotek.key.*;
import org.jetbrains.annotations.NotNull;

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
    public <X extends Key> void importKey(String label, EncodedKey encodedKey, Class<X> keyType, KeyStoreAccessToken keyStoreAccessToken) throws KeyStoreAccessException, InvalidKeyException {
        importKey(label, cryptoEngine.readKey(keyType,encodedKey), keyStoreAccessToken);
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

    @NotNull
    @Override
    public RSAKeyPair generateRSAKeyPair(String keyLabel, int keySize) throws KeyStoreAccessException {
        final RSAKeyPair key = cryptoEngine.generateRSAKeyPair(keySize);
        importKey(keyLabel, key);
        return key;
    }

    @NotNull
    @Override
    public AESKey generateAESKey(String keyLabel, int keySize) throws KeyStoreAccessException {
        final AESKey key = cryptoEngine.generateAESKey(keySize);
        importKey(keyLabel, key);
        return key;
    }

    @NotNull
    @Override
    public AESKey generateAESKey(String keyLabel, int keySize, DHPrivateKey dhPrivateKey, DHPublicKey dhPublicKey) throws InvalidKeyException, KeyStoreAccessException {
        final AESKey key = cryptoEngine.generateAESKey(keySize, dhPrivateKey, dhPublicKey);
        importKey(keyLabel, key);
        return key;
    }

    @NotNull
    @Override
    public AESKey generatePBEAESKey(String keyLabel, char[] credential, int iterations, byte[] salt, int keyLen) throws KeyStoreAccessException {
        final AESKey key = cryptoEngine.generatePBEAESKey(credential, iterations, salt, keyLen);
        importKey(keyLabel, key);
        return key;
    }

    @NotNull
    @Override
    public HMACKey generateHMACKey(String keyLabel, DigestAlgorithm digestAlgorithm) throws KeyStoreAccessException {
        final HMACKey key = cryptoEngine.generateHMACKey(digestAlgorithm);
        importKey(keyLabel, key);
        return key;
    }

    @NotNull
    @Override
    public HMACKey generateHMACKey(String keyLabel, DigestAlgorithm digestAlgorithm, DHPrivateKey dhPrivateKey, DHPublicKey dhPublicKey) throws InvalidKeyException, KeyStoreAccessException {
        final HMACKey key = cryptoEngine.generateHMACKey(digestAlgorithm, dhPrivateKey, dhPublicKey);
        importKey(keyLabel, key);
        return key;
    }
}
