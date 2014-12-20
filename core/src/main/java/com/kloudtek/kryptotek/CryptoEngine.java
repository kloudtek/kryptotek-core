/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek;

import org.jetbrains.annotations.NotNull;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

/**
 * Interface for cryptography providers
 */
public abstract class CryptoEngine {
    public abstract Key generateKey(Key.Type type, int len);

    public abstract Key readKey(@NotNull EncodedKey encodedKey, @NotNull Key.Type type) throws InvalidKeyException;

    public abstract Key readKey(@NotNull byte[] encodedKey, @NotNull Key.Type type) throws InvalidKeyException;

    /**
     * Encrypt data using specified key.
     * <i>Please note that when using RSA crypto, the JCE implementation won't support compatibility mode set to false</i>
     * @param key Cryptographic key
     * @param data Data to encrypt
     * @param compatibilityMode If this flag is true a weaker algorithm that works on all implementations will be used. If set to false a better algorithm will be used, but this might not work with all crypto engines.
     * @return Encrypted data
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public abstract byte[] encrypt(@NotNull Key key, @NotNull byte[] data, boolean compatibilityMode) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException;

    public abstract byte[] encrypt(@NotNull Key key, @NotNull SymmetricAlgorithm symmetricAlgorithm, int symmetricKeySize, @NotNull byte[] data, boolean compatibilityMode) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException;

    public abstract byte[] decrypt(@NotNull Key key, @NotNull byte[] data, boolean compatibilityMode) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException;

    public abstract byte[] decrypt(@NotNull Key key, @NotNull SymmetricAlgorithm symmetricAlgorithm, int symmetricKeySize, @NotNull byte[] data, boolean compatibilityMode) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException;

    public abstract byte[] sign(Key key, byte[] data) throws SignatureException, InvalidKeyException;

    public abstract byte[] sign(@NotNull Key key, @NotNull DigestAlgorithm digestAlgorithms, @NotNull byte[] data) throws SignatureException, InvalidKeyException;

    public abstract void verifySignature(@NotNull Key key, @NotNull byte[] data, @NotNull byte[] signature) throws SignatureException, InvalidKeyException;

    public abstract void verifySignature(@NotNull Key key, @NotNull DigestAlgorithm digestAlgorithms, @NotNull byte[] data, @NotNull byte[] signature) throws SignatureException, InvalidKeyException;

    public abstract SecretKey generatePBEAESKey(char[] key, int iterations, byte[] salt, int keyLen) throws InvalidKeySpecException;

    /**
     * Create a digest from a byte array
     *
     * @param data Data to create digest from
     * @param alg  Algorithm to use for digest
     * @return digest value
     */
    public abstract byte[] digest(byte[] data, DigestAlgorithm alg);

    public abstract Digest digest(DigestAlgorithm alg);

    // Old API to deprecate

    /**
     * Generate a private key using a symmetric algorithm
     *
     * @param alg     Symmetric algorithm
     * @param keysize Key size
     * @return secret key
     */
    public abstract SecretKey generateSecretKey(SymmetricAlgorithm alg, int keysize);

    /**
     * Generate an HMAC key
     *
     * @param algorithm digest algorithm
     * @return secret key
     */
    public abstract SecretKey generateHmacKey(DigestAlgorithm algorithm);

    /**
     * Generate an AES secret key
     *
     * @param keySize key size
     * @return key size
     */
    public SecretKey generateAesKey(int keySize) {
        return generateSecretKey(SymmetricAlgorithm.AES, keySize);
    }

    public SecretKey generateAes128Key() {
        return generateSecretKey(SymmetricAlgorithm.AES, 128);
    }

    public SecretKey generateAes256Key() {
        return generateSecretKey(SymmetricAlgorithm.AES, 256);
    }

    public SecretKey generateAes192Key() {
        return generateSecretKey(SymmetricAlgorithm.AES, 192);
    }

    public abstract KeyPair generateKeyPair(AsymmetricAlgorithm alg, int keysize);

    public KeyPair generateRSA2048KeyPair() {
        return generateKeyPair(AsymmetricAlgorithm.RSA, 2048);
    }

    public KeyPair generateRSA4096KeyPair() {
        return generateKeyPair(AsymmetricAlgorithm.RSA, 4096);
    }

    /**
     * Read an X509 Encoded S_RSA public key
     *
     * @param key X509 encoded rsa key
     * @return Public key object
     * @throws java.security.spec.InvalidKeySpecException If the key is invalid
     */
    public abstract java.security.interfaces.RSAPublicKey readRSAPublicKey(@NotNull byte[] key) throws InvalidKeySpecException;

    /**
     * Read a PKCS8 Encoded S_RSA private key
     *
     * @param encodedPriKey PKCS8 encoded rsa key
     * @return Public key object
     * @throws InvalidKeySpecException If the key is invalid
     */
    public abstract PrivateKey readRSAPrivateKey(@NotNull byte[] encodedPriKey) throws InvalidKeySpecException;

    public abstract SecretKey readAESKey(@NotNull byte[] encodedAesKey);

    public abstract SecretKey readHMACKey(@NotNull DigestAlgorithm algorithm, @NotNull byte[] encodedKey);

    public abstract byte[] hmac(DigestAlgorithm algorithm, SecretKey key, byte[] data) throws InvalidKeyException;

    public abstract byte[] hmacSha1(SecretKey key, byte[] data) throws InvalidKeyException;

    public abstract byte[] hmacSha256(SecretKey key, byte[] data) throws InvalidKeyException;

    public abstract byte[] hmacSha512(SecretKey key, byte[] data) throws InvalidKeyException;

    public abstract byte[] aesEncrypt(byte[] key, byte[] data) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException;

    public abstract byte[] aesEncrypt(SecretKey key, byte[] data) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException;

    public abstract byte[] aesDecrypt(byte[] key, byte[] data) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException;

    public abstract byte[] aesDecrypt(SecretKey key, byte[] data) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException;

    public abstract byte[] encrypt(java.security.Key key, byte[] data, String alg) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException;

    public abstract byte[] decrypt(java.security.Key key, byte[] data, String alg) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException;

    public abstract byte[] crypt(java.security.Key key, byte[] data, String alg, int mode) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException;

    public abstract byte[] rsaEncrypt(byte[] key, byte[] data) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException;

    public abstract byte[] rsaEncrypt(PublicKey key, byte[] data) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException;

    public abstract byte[] rsaDecrypt(byte[] key, byte[] data) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException;

    public abstract byte[] rsaDecrypt(PrivateKey key, byte[] data) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException;

    public abstract byte[] rsaSign(DigestAlgorithm digestAlgorithms, PrivateKey key, byte[] data) throws InvalidKeyException, SignatureException;

    public abstract void rsaVerifySignature(DigestAlgorithm digestAlgorithms, PublicKey key, byte[] data, byte[] signature) throws InvalidKeyException, SignatureException;

    public abstract byte[] sign(String algorithm, PrivateKey key, byte[] data) throws SignatureException, InvalidKeyException;

    public abstract void verifySignature(String algorithm, PublicKey key, byte[] data, byte[] signature) throws SignatureException, InvalidKeyException;
}
