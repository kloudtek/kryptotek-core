/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.keystore;

import com.kloudtek.kryptotek.DigestAlgorithm;
import com.kloudtek.kryptotek.EncodedKey;
import com.kloudtek.kryptotek.Key;
import com.kloudtek.kryptotek.key.*;
import org.jetbrains.annotations.NotNull;

import java.security.InvalidKeyException;

/**
 * Created by yannick on 22/11/2014.
 */
public interface KeyStore {
    KeyStoreAccessToken getAccessToken(KeyStoreCredential credential) throws CredentialInvalidException, KeyStoreAccessException;

    <X extends com.kloudtek.kryptotek.Key> X getKey(Class<X> keyClass, String keyLabel, KeyStoreAccessToken keyStoreAccessToken) throws KeyNotFoundException, KeyStoreAccessException, InvalidKeyException;

    com.kloudtek.kryptotek.Key getKey(String keyLabel, KeyStoreAccessToken keyStoreAccessToken) throws KeyNotFoundException, KeyStoreAccessException, InvalidKeyException;

    com.kloudtek.kryptotek.Key getKey(String keyLabel) throws KeyNotFoundException, KeyStoreAccessException, InvalidKeyException;

    <X extends Key> void importKey(String label, EncodedKey encodedKey, Class<X> keyType, KeyStoreAccessToken keyStoreAccessToken) throws KeyStoreAccessException, InvalidKeyException;

    void importKey(String label, com.kloudtek.kryptotek.Key key, KeyStoreAccessToken keyStoreAccessToken) throws KeyStoreAccessException;

    void importKey(String label, com.kloudtek.kryptotek.Key key) throws KeyStoreAccessException;

    void deleteKey(String label) throws KeyStoreAccessException;

    @NotNull
    RSAKeyPair generateRSAKeyPair(String keyLabel, int keySize) throws KeyStoreAccessException;

    @NotNull
    AESKey generateAESKey(String keyLabel, int keySize) throws KeyStoreAccessException;

    @NotNull
    AESKey generateAESKey(String keyLabel, int keySize, DHPrivateKey dhPrivateKey, DHPublicKey dhPublicKey) throws InvalidKeyException, KeyStoreAccessException;

    @NotNull
    AESKey generatePBEAESKey(String keyLabel, char[] credential, int iterations, byte[] salt, int keyLen) throws KeyStoreAccessException;

    @NotNull
    HMACKey generateHMACKey(String keyLabel, DigestAlgorithm digestAlgorithm) throws KeyStoreAccessException;

    @NotNull
    HMACKey generateHMACKey(String keyLabel, DigestAlgorithm digestAlgorithm, DHPrivateKey dhPrivateKey, DHPublicKey dhPublicKey) throws InvalidKeyException, KeyStoreAccessException;

    @NotNull
    DHKeyPair generateDHKeyPair(String keyLabel, DHParameters parameterSpec) throws KeyStoreAccessException;
}
