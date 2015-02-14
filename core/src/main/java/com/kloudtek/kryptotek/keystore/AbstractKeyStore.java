/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.keystore;

import com.kloudtek.kryptotek.CryptoEngine;
import com.kloudtek.kryptotek.DigestAlgorithm;
import com.kloudtek.kryptotek.EncodedKey;
import com.kloudtek.kryptotek.Key;
import com.kloudtek.kryptotek.key.*;
import org.jetbrains.annotations.NotNull;

import java.security.InvalidKeyException;

/**
 * Created by yannick on 22/11/2014.
 */
public abstract class AbstractKeyStore implements KeyStore {
    protected CryptoEngine cryptoEngine;

    protected AbstractKeyStore(CryptoEngine cryptoEngine) {
        this.cryptoEngine = cryptoEngine;
    }

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

    @Override
    public <X extends Key> void importKey(String label, EncodedKey encodedKey, Class<X> keyType, KeyStoreAccessToken keyStoreAccessToken) throws KeyStoreAccessException, InvalidKeyException {
        importKey(label, cryptoEngine.readKey(keyType, encodedKey), keyStoreAccessToken);
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

    @NotNull
    @Override
    public DHKeyPair generateDHKeyPair(String keyLabel, DHParameters parameterSpec) throws KeyStoreAccessException {
        final DHKeyPair keyPair = cryptoEngine.generateDHKeyPair(parameterSpec);
        importKey(keyLabel, keyPair);
        return keyPair;
    }
}
