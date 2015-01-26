/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek;

import com.kloudtek.kryptotek.key.*;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.DHParameterSpec;
import java.security.InvalidKeyException;
import java.security.SignatureException;

/**
 * Interface for cryptography providers
 */
public abstract class CryptoEngine {
    public static final String AES_CBC_PKCS_5_PADDING = "AES/ECB/PKCS5PADDING";
    public static final String RSA_ECB_OAEPPADDING = "RSA/ECB/OAEPWithSHA1AndMGF1Padding";
    public static final String RSA_ECB_PKCS1_PADDING = "RSA/ECB/PKCS1Padding";
    protected boolean defaultCompatibilityMode;

    public CryptoEngine(boolean defaultCompatibilityMode) {
        this.defaultCompatibilityMode = defaultCompatibilityMode;
    }

    public CryptoEngine() {
        defaultCompatibilityMode = true;
    }

    public boolean isDefaultCompatibilityMode() {
        return defaultCompatibilityMode;
    }

    public void setDefaultCompatibilityMode(boolean defaultCompatibilityMode) {
        this.defaultCompatibilityMode = defaultCompatibilityMode;
    }

    @NotNull
    public abstract RSAKeyPair generateRSAKeyPair(int keySize);

    @NotNull
    public abstract AESKey generateAESKey(int keySize);

    @NotNull
    public abstract AESKey generatePBEAESKey(char[] key, int iterations, byte[] salt, int keyLen);

    @NotNull
    public abstract HMACKey generateHMACKey(DigestAlgorithm digestAlgorithm);

    @NotNull
    public abstract SimpleCertificate generateSimpleCertificate(String subject, PublicKey publicKey);

    @NotNull
    public abstract DHKeyPair generateDHKeyPair(DHParameterSpec parameterSpec);

    @Nullable
    public <K extends Key> K generateNonStandardKey(@NotNull Class<K> keyType, int keySize) {
        return null;
    }

    @NotNull
    public <K extends Key> K generateKey(@NotNull Class<K> keyType, int keySize) {
        if (AESKey.class.isAssignableFrom(keyType)) {
            return keyType.cast(generateAESKey(keySize));
        } else if (HMACSHA1Key.class.isAssignableFrom(keyType)) {
            return keyType.cast(generateHMACKey(DigestAlgorithm.SHA1));
        } else if (HMACSHA256Key.class.isAssignableFrom(keyType)) {
            return keyType.cast(generateHMACKey(DigestAlgorithm.SHA256));
        } else if (HMACSHA512Key.class.isAssignableFrom(keyType)) {
            return keyType.cast(generateHMACKey(DigestAlgorithm.SHA512));
        } else if (RSAKeyPair.class.isAssignableFrom(keyType)) {
            return keyType.cast(generateRSAKeyPair(keySize));
        } else {
            K key = generateNonStandardKey(keyType, keySize);
            if (key == null) {
                throw new IllegalArgumentException("Key type not supported: " + keyType.getName());
            } else {
                return key;
            }
        }
    }

    public HMACKey readHMACKey(DigestAlgorithm digestAlgorithm, byte[] rawEncodedKey) throws InvalidKeyException {
        switch (digestAlgorithm) {
            case SHA1:
                return readKey(HMACSHA1Key.class, rawEncodedKey);
            case SHA256:
                return readKey(HMACSHA256Key.class, rawEncodedKey);
            case SHA512:
                return readKey(HMACSHA512Key.class, rawEncodedKey);
            default:
                throw new IllegalArgumentException("Unsupported HMAC algorithm: " + digestAlgorithm.name());
        }
    }

    public AESKey readAESKey(byte[] rawEncodedKey) throws InvalidKeyException {
        return readKey(AESKey.class, rawEncodedKey);
    }

    public RSAKeyPair readRSAKeyPair(byte[] customEncodedKey) throws InvalidKeyException {
        return readKey(RSAKeyPair.class, customEncodedKey);
    }

    public RSAPublicKey readRSAPublicKey(byte[] x509encodedKey) throws InvalidKeyException {
        return readKey(RSAPublicKey.class, x509encodedKey);
    }

    public RSAPrivateKey readRSAPrivateKey(byte[] pkcs8encodedKey) throws InvalidKeyException {
        return readKey(RSAPrivateKey.class, pkcs8encodedKey);
    }

    public <K extends Key> K readSerializedKey(@NotNull Class<K> keyType, byte[] serializedKey) throws InvalidKeyException {
        Key key = readSerializedKey(serializedKey);
        if (keyType.isInstance(key)) {
            return keyType.cast(key);
        } else {
            throw new InvalidKeyException("Key " + key.getClass().getName() + " not of type " + keyType.getName());
        }
    }

    public abstract Key readSerializedKey(byte[] serializedKey) throws InvalidKeyException;

    public abstract <K extends Key> K readKey(@NotNull Class<K> keyType, @NotNull EncodedKey encodedKey) throws InvalidKeyException;

    public abstract <K extends Key> K readKey(@NotNull Class<K> keyType, @NotNull byte[] encodedKey) throws InvalidKeyException;

    /**
     * Encrypt data using specified key using the default compatibility mode (see {@link #setDefaultCompatibilityMode(boolean)}).
     * <i>Please note that when using RSA crypto, the JCE implementation won't support compatibility mode set to false</i>
     *
     * @param compatibilityMode If this flag is true a weaker algorithm that works on all implementations will be used. If set to false a better algorithm will be used, but this might not work with all crypto engines.
     * @param key               Cryptographic key
     * @param data              Data to encrypt
     * @return Encrypted data
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public byte[] encrypt(@NotNull EncryptionKey key, @NotNull byte[] data) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return encrypt(key, data, defaultCompatibilityMode);
    }

    public byte[] encrypt(@NotNull EncryptionKey key, @NotNull SymmetricAlgorithm symmetricAlgorithm, int symmetricKeySize, @NotNull byte[] data) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return encrypt(key, symmetricAlgorithm, symmetricKeySize, data, defaultCompatibilityMode);
    }

    public byte[] rsaEncrypt(@NotNull byte[] x509encodedPublicKey, @NotNull SymmetricAlgorithm symmetricAlgorithm, int symmetricKeySize, @NotNull byte[] data) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return encrypt(readRSAPublicKey(x509encodedPublicKey), symmetricAlgorithm, symmetricKeySize, data, defaultCompatibilityMode);
    }

    public byte[] rsaEncrypt(@NotNull byte[] x509encodedPublicKey, @NotNull byte[] data) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return encrypt(readRSAPublicKey(x509encodedPublicKey), data, defaultCompatibilityMode);
    }

    public byte[] aesEncrypt(@NotNull byte[] rawAesEncodedKey, @NotNull byte[] data) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return encrypt(readAESKey(rawAesEncodedKey), data, defaultCompatibilityMode);
    }

    public byte[] decrypt(@NotNull DecryptionKey key, @NotNull byte[] data) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return decrypt(key, data, defaultCompatibilityMode);
    }

    public byte[] decrypt(@NotNull DecryptionKey key, @NotNull SymmetricAlgorithm symmetricAlgorithm, int symmetricKeySize, @NotNull byte[] data) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return decrypt(key, symmetricAlgorithm, symmetricKeySize, data, defaultCompatibilityMode);
    }

    public byte[] rsaDecrypt(@NotNull byte[] pkcs8encodedPublicKey, @NotNull SymmetricAlgorithm symmetricAlgorithm, int symmetricKeySize, @NotNull byte[] data) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return decrypt(readRSAPrivateKey(pkcs8encodedPublicKey), symmetricAlgorithm, symmetricKeySize, data, defaultCompatibilityMode);
    }

    public byte[] rsaDecrypt(@NotNull byte[] pkcs8encodedPublicKey, @NotNull byte[] data) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return decrypt(readRSAPrivateKey(pkcs8encodedPublicKey), data, defaultCompatibilityMode);
    }

    public byte[] aesDecrypt(@NotNull byte[] rawAesEncodedKey, @NotNull byte[] data) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return decrypt(readAESKey(rawAesEncodedKey), data, defaultCompatibilityMode);
    }

    /**
     * Encrypt data using specified key.
     * <i>Please note that when using RSA crypto, the JCE implementation won't support compatibility mode set to false</i>
     *
     * @param key               Cryptographic key
     * @param data              Data to encrypt
     * @param compatibilityMode If this flag is true a weaker algorithm that works on all implementations will be used. If set to false a better algorithm will be used, but this might not work with all crypto engines.
     * @return Encrypted data
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public abstract byte[] encrypt(@NotNull EncryptionKey key, @NotNull byte[] data, boolean compatibilityMode) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException;

    public abstract byte[] encrypt(@NotNull EncryptionKey key, @NotNull byte[] data, String cipherAlgorithm) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException;

    public abstract byte[] encrypt(@NotNull EncryptionKey key, @NotNull SymmetricAlgorithm symmetricAlgorithm, int symmetricKeySize, @NotNull byte[] data, boolean compatibilityMode) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException;

    public abstract byte[] decrypt(@NotNull DecryptionKey key, @NotNull byte[] data, boolean compatibilityMode) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException;

    public abstract byte[] decrypt(@NotNull DecryptionKey key, @NotNull SymmetricAlgorithm symmetricAlgorithm, int symmetricKeySize, @NotNull byte[] data, boolean compatibilityMode) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException;

    public abstract byte[] decrypt(@NotNull DecryptionKey key, @NotNull SymmetricAlgorithm symmetricAlgorithm, @NotNull String symmetricAlgorithmCipher, int symmetricKeySize, @NotNull byte[] data, @NotNull String cipherAlgorithm) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException;

    public byte[] sign(@NotNull SigningKey key, @NotNull byte[] data) throws InvalidKeyException {
        return sign(key, null, data);
    }

    public abstract byte[] sign(@NotNull SigningKey key, @Nullable DigestAlgorithm digestAlgorithms, @NotNull byte[] data) throws InvalidKeyException;

    public byte[] rsaSign(@NotNull byte[] pkcs8encodedPrivateKey, @NotNull DigestAlgorithm digestAlgorithms, @NotNull byte[] data) throws InvalidKeyException {
        return sign(readRSAPrivateKey(pkcs8encodedPrivateKey), digestAlgorithms, data);
    }

    public void verifySignature(@NotNull SignatureVerificationKey key, @NotNull byte[] data, @NotNull byte[] signature) throws SignatureException, InvalidKeyException {
        verifySignature(key, null, data, signature);
    }

    public abstract void verifySignature(@NotNull SignatureVerificationKey key, @Nullable DigestAlgorithm digestAlgorithms, @NotNull byte[] data, @NotNull byte[] signature) throws SignatureException, InvalidKeyException;

    public void rsaVerifySignature(@NotNull byte[] x509encodedPrivateKey, @NotNull DigestAlgorithm digestAlgorithms, @NotNull byte[] data, @NotNull byte[] signature) throws SignatureException, InvalidKeyException {
        verifySignature(readRSAPublicKey(x509encodedPrivateKey), digestAlgorithms, data, signature);
    }

    /**
     * Create a digest from a byte array
     *
     * @param data Data to create digest from
     * @param alg  Algorithm to use for digest
     * @return digest value
     */
    public abstract byte[] digest(byte[] data, DigestAlgorithm alg);

    public byte[] md5(byte[] data) {
        return digest(data, DigestAlgorithm.MD5);
    }

    public byte[] sha1(byte[] data) {
        return digest(data, DigestAlgorithm.SHA1);
    }

    public byte[] sha256(byte[] data) {
        return digest(data, DigestAlgorithm.SHA256);
    }

    public byte[] sha512(byte[] data) {
        return digest(data, DigestAlgorithm.SHA512);
    }

    public abstract Digest digest(DigestAlgorithm alg);
}
