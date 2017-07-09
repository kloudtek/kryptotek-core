/*
 * Copyright (c) 2016 Kloudtek Ltd
 */

package com.kloudtek.kryptotek;

import com.kloudtek.kryptotek.jce.JCECryptoEngine;
import com.kloudtek.kryptotek.key.*;
import com.kloudtek.util.Base64;
import com.kloudtek.util.UnexpectedException;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.security.auth.DestroyFailedException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.logging.Logger;

/**
 * Various cryptographic methods
 */
public class CryptoUtils {
    private static final char[] symbolsAllCaps;
    private static final char[] symbols;
    private static final Logger logger = Logger.getLogger(CryptoUtils.class.getName());
    static CryptoEngine engine;
    private static final SecureRandom rng = new SecureRandom();

    static {
        engine = createEngine("com.kloudtek.kryptotek.test.TestCryptoEngine");
        if (engine == null) {
            engine = new JCECryptoEngine();
        }
        StringBuilder tmp = new StringBuilder();
        for (char c = '2'; c <= '9'; c++) {
            tmp.append(c);
        }
        for (char c = 'A'; c <= 'Z'; c++) {
            if (c != 'I' && c != 'O') {
                tmp.append(c);
            }
        }
        symbolsAllCaps = tmp.toString().toCharArray();
        for (char c = 'a'; c <= 'z'; c++) {
            if (c != 'l' && c != 'o') {
                tmp.append(c);
            }
        }
        symbols = tmp.toString().toCharArray();
    }

    private static CryptoEngine createEngine(String classname) {
        try {
            Class<?> cl = Class.forName(classname);
            return (CryptoEngine) cl.newInstance();
        } catch (ClassNotFoundException e) {
            return null;
        } catch (InstantiationException e) {
            throw new UnexpectedException(e);
        } catch (IllegalAccessException e) {
            throw new UnexpectedException(e);
        }
    }

    public static CryptoEngine getEngine() {
        return engine;
    }

    /**
     * Create random bytes to be used as salt
     *
     * @param len salt size
     * @return Random data of size len
     */
    public static byte[] genSalt(int len) {
        byte[] salt = new byte[len];
        rng.nextBytes(salt);
        return salt;
    }

    /**
     * Extract salt from a byte array (assuming salt at the start of array)
     *
     * @param dataWithSalt Salt lenght
     * @return Data and salt
     */
    public static DataAndSalt splitSalt(byte[] dataWithSalt, int saltLen) {
        byte[] salt = Arrays.copyOfRange(dataWithSalt, 0, saltLen);
        byte[] data = Arrays.copyOfRange(dataWithSalt, saltLen, dataWithSalt.length);
        return new DataAndSalt(data, salt);
    }

    /**
     * Attempts to destroy an object's data
     *
     * @param object Object to destroy
     */
    public static void destroy(Object object) {
        if (object instanceof byte[]) {
            zero((byte[]) object);
        } else if (object instanceof char[]) {
            zero((char[]) object);
        } else if (object instanceof Destroyable) {
            ((Destroyable) object).destroy();
        } else if (object instanceof javax.security.auth.Destroyable && !((javax.security.auth.Destroyable) object).isDestroyed()) {
            try {
                ((javax.security.auth.Destroyable) object).destroy();
            } catch (DestroyFailedException e) {
                // JCE keys generally fail even then they pretend to be destroyable so don't log other those will spam
            }
        }
    }

    /**
     * Split a key into multiple keys using XOR
     *
     * @param key    key to split
     * @param amount How many new keys should be generated
     * @return List of keys
     */
    public static byte[][] splitKey(byte[] key, int amount) {
        int keyLen = key.length;
        ArrayList<byte[]> keys = new ArrayList<byte[]>(amount);
        if (amount < 0) {
            throw new IllegalArgumentException("Amount must be 1 or more");
        } else if (amount == 1) {
            keys.add(key);
        } else {
            SecureRandom rng = new SecureRandom();
            byte[] xorVal = key;
            for (int i = 0; i < amount - 1; i++) {
                byte[] newKey = new byte[keyLen];
                rng.nextBytes(newKey);
                keys.add(newKey);
                xorVal = xor(xorVal, newKey);
            }
            keys.add(xorVal);
        }
        return keys.toArray(new byte[key.length][amount]);
    }

    /**
     * fill the array with zeros
     *
     * @param data Data to zero
     */
    public static void zero(@NotNull char[]... data) {
        for (char[] chars : data) {
            if (chars != null) {
                Arrays.fill(chars, '\u0000');
            }
        }
    }

    /**
     * fill the array with zeros
     *
     * @param data Data to zero
     */
    public static void zero(@NotNull byte[]... data) {
        for (byte[] bytes : data) {
            if (bytes != null) {
                Arrays.fill(bytes, (byte) 0);
            }
        }
    }

    /**
     * fill the array with zeros
     *
     * @param data Data to zero
     */
    public static void zero(CharBuffer data) {
        zero(data.array());
    }

    /**
     * fill the array with zeros
     *
     * @param data Data to zero
     */
    public static void zero(ByteBuffer data) {
        zero(data.array());
    }

    public static byte[] mergeSplitKey(byte[]... keys) {
        if (keys == null) {
            throw new IllegalArgumentException("There must be at least one key");
        } else {
            return mergeSplitKey(Arrays.asList(keys));
        }
    }

    public static byte[] mergeSplitKey(Collection<byte[]> keys) {
        if (keys == null || keys.isEmpty()) {
            throw new IllegalArgumentException("There must be at least one key");
        } else if (keys.size() == 1) {
            return keys.iterator().next();
        } else {
            Iterator<byte[]> i = keys.iterator();
            byte[] val = i.next();
            int len = val.length;
            while (i.hasNext()) {
                byte[] next = i.next();
                if (next.length != len) {
                    throw new IllegalArgumentException("All keys must have the same length");
                }
                val = xor(val, next);
            }
            return val;
        }
    }

    private static byte[] xor(byte[] b1, byte[] b2) {
        byte[] val = new byte[b1.length];
        for (int i = 0; i < b1.length; i++) {
            val[i] = (byte) (b1[i] ^ b2[i]);
        }
        return val;
    }

    /**
     * Retrieve shared instance of {@link SecureRandom}
     *
     * @return {@link SecureRandom} instance
     */
    public static SecureRandom rng() {
        return rng;
    }

    public static char[] generateRandomPassword(int len, boolean allCaps) {
        char[] charSet = allCaps ? symbolsAllCaps : symbols;
        char[] pw = new char[len];
        for (int i = 0; i < len; i++) {
            pw[i] = charSet[rng.nextInt(charSet.length)];
        }
        return pw;
    }

    public static String fingerprint(byte[] data) {
        return new Base64(-1, new byte[0], true).encodeAsString(DigestUtils.md5(data)).toUpperCase();
    }

    // START DELEGATED CRYPTO ENGINE FUNCTIONS

    public static boolean isDefaultCompatibilityMode() {
        return engine.isDefaultCompatibilityMode();
    }

    @NotNull
    public static Certificate generateCertificate(String subject, PublicKey publicKey) {
        return engine.generateCertificate(subject, publicKey);
    }

    public static <K extends Key> K readKey(@NotNull Class<K> keyType, @NotNull byte[] encodedKey) throws InvalidKeyException {
        return engine.readKey(keyType, encodedKey);
    }

    public static RSAPrivateKey readRSAPrivateKey(byte[] pkcs8encodedKey) throws InvalidKeyException {
        return engine.readRSAPrivateKey(pkcs8encodedKey);
    }

    public static byte[] encrypt(@NotNull EncryptionKey key, @NotNull SymmetricAlgorithm symmetricAlgorithm, int symmetricKeySize, @NotNull byte[] data) throws EncryptionException {
        return engine.encrypt(key, symmetricAlgorithm, symmetricKeySize, data);
    }

    public static byte[] sha256(byte[] data) {
        return engine.sha256(data);
    }

    public static void verifySignature(@NotNull SignatureVerificationKey key, @NotNull byte[] data, @NotNull byte[] signature) throws SignatureException, InvalidKeyException {
        engine.verifySignature(key, data, signature);
    }

    public static byte[] decrypt(@NotNull DecryptionKey key, @NotNull SymmetricAlgorithm symmetricAlgorithm, int symmetricKeySize, @NotNull byte[] data) throws DecryptionException {
        return engine.decrypt(key, symmetricAlgorithm, symmetricKeySize, data);
    }

    public static byte[] rsaDecrypt(@NotNull byte[] pkcs8encodedPublicKey, @NotNull byte[] data) throws DecryptionException {
        return engine.rsaDecrypt(pkcs8encodedPublicKey, data);
    }

    public static Key readSerializedKey(byte[] serializedKey) throws InvalidKeyException {
        return engine.readSerializedKey(serializedKey);
    }

    public static byte[] encrypt(@NotNull EncryptionKey key, @NotNull SymmetricAlgorithm symmetricAlgorithm,
                                 @NotNull String symmetricAlgorithmCipher, int symmetricKeySize, @NotNull byte[] data, @NotNull String cipherAlgorithm) throws EncryptionException {
        return engine.encrypt(key, symmetricAlgorithm, symmetricAlgorithmCipher, symmetricKeySize, data, cipherAlgorithm);
    }

    public static byte[] decrypt(@NotNull DecryptionKey key, @NotNull SymmetricAlgorithm symmetricAlgorithm, int symmetricKeySize, @NotNull byte[] data, boolean compatibilityMode) throws DecryptionException {
        return engine.decrypt(key, symmetricAlgorithm, symmetricKeySize, data, compatibilityMode);
    }

    public static byte[] aesDecrypt(@NotNull byte[] rawAesEncodedKey, @NotNull byte[] data) throws DecryptionException {
        return engine.aesDecrypt(rawAesEncodedKey, data);
    }

    public static <K extends Key> K readSerializedKey(@NotNull Class<K> keyType, byte[] serializedKey) throws InvalidKeyException {
        return engine.readSerializedKey(keyType, serializedKey);
    }

    @Nullable
    public static <K extends Key> K generateNonStandardKey(@NotNull Class<K> keyType, int keySize) {
        return engine.generateNonStandardKey(keyType, keySize);
    }

    public static byte[] encrypt(@NotNull EncryptionKey key, @NotNull byte[] data, String cipherAlgorithm) throws EncryptionException {
        return engine.encrypt(key, data, cipherAlgorithm);
    }

    @NotNull
    public static DHParameters generateDHParameters() {
        return engine.generateDHParameters();
    }

    public static byte[] rsaEncrypt(@NotNull byte[] x509encodedPublicKey, @NotNull byte[] data) throws EncryptionException {
        return engine.rsaEncrypt(x509encodedPublicKey, data);
    }

    public static void verifySignature(@NotNull SignatureVerificationKey key, @Nullable DigestAlgorithm digestAlgorithms, @NotNull byte[] data, @NotNull byte[] signature) throws SignatureException, InvalidKeyException {
        engine.verifySignature(key, digestAlgorithms, data, signature);
    }

    public static <K extends Key> K readKey(@NotNull Class<K> keyType, @NotNull EncodedKey encodedKey) throws InvalidKeyException {
        return engine.readKey(keyType, encodedKey);
    }

    public static byte[] md5(byte[] data) {
        return engine.md5(data);
    }

    public static byte[] pbkdf2(DigestAlgorithm digestAlgorithms, char[] password, int iterations, byte[] salt, int keyLen) {
        return engine.pbkdf2(digestAlgorithms, password, iterations, salt, keyLen);
    }

    public static byte[] encrypt(@NotNull EncryptionKey key, @NotNull SymmetricAlgorithm symmetricAlgorithm, int symmetricKeySize, @NotNull byte[] data, boolean compatibilityMode) throws EncryptionException {
        return engine.encrypt(key, symmetricAlgorithm, symmetricKeySize, data, compatibilityMode);
    }

    public static byte[] rsaDecrypt(@NotNull byte[] pkcs8encodedPublicKey, @NotNull SymmetricAlgorithm symmetricAlgorithm, int symmetricKeySize, @NotNull byte[] data) throws DecryptionException {
        return engine.rsaDecrypt(pkcs8encodedPublicKey, symmetricAlgorithm, symmetricKeySize, data);
    }

    public static byte[] aesEncrypt(@NotNull byte[] rawAesEncodedKey, @NotNull byte[] data) throws EncryptionException {
        return engine.aesEncrypt(rawAesEncodedKey, data);
    }

    public static DHPublicKey readDHPublicKey(byte[] x509encodedKey) throws InvalidKeyException {
        return engine.readDHPublicKey(x509encodedKey);
    }

    @NotNull
    public static DHKeyPair generateDHKeyPair(DHParameters parameterSpec) {
        return engine.generateDHKeyPair(parameterSpec);
    }

    public static byte[] decrypt(@NotNull DecryptionKey key, @NotNull byte[] data) throws DecryptionException {
        return engine.decrypt(key, data);
    }

    public static byte[] decrypt(@NotNull DecryptionKey key, @NotNull SymmetricAlgorithm symmetricAlgorithm, @NotNull String symmetricAlgorithmCipher, int symmetricKeySize, @NotNull byte[] data, @NotNull String cipherAlgorithm) throws DecryptionException {
        return engine.decrypt(key, symmetricAlgorithm, symmetricAlgorithmCipher, symmetricKeySize, data, cipherAlgorithm);
    }

    @NotNull
    public static AESKey generateAESKey(AESKeyLen keySize) {
        return engine.generateAESKey(keySize);
    }

    @NotNull
    public static HMACKey generateHMACKey(DigestAlgorithm digestAlgorithm) {
        return engine.generateHMACKey(digestAlgorithm);
    }

    public static RSAPublicKey readRSAPublicKey(byte[] x509encodedKey) throws InvalidKeyException {
        return engine.readRSAPublicKey(x509encodedKey);
    }

    @NotNull
    public static HMACKey generateHMACKey(DigestAlgorithm digestAlgorithm, DHPrivateKey dhPrivateKey, DHPublicKey dhPublicKey) throws InvalidKeyException {
        return engine.generateHMACKey(digestAlgorithm, dhPrivateKey, dhPublicKey);
    }

    @NotNull
    public static AESKey generateAESKey(AESKeyLen keySize, DHPrivateKey dhPrivateKey, DHPublicKey dhPublicKey) throws InvalidKeyException {
        return engine.generateAESKey(keySize, dhPrivateKey, dhPublicKey);
    }

    @NotNull
    public static DHParameters generateDHParameters(int keySize) {
        return engine.generateDHParameters(keySize);
    }

    public static byte[] sha1(byte[] data) {
        return engine.sha1(data);
    }

    public static byte[] encrypt(@NotNull EncryptionKey key, @NotNull byte[] data) throws EncryptionException {
        return engine.encrypt(key, data);
    }

    public static byte[] sha512(byte[] data) {
        return engine.sha512(data);
    }

    public static Digest digest(DigestAlgorithm alg) {
        return engine.digest(alg);
    }

    public static byte[] decrypt(@NotNull DecryptionKey key, @NotNull byte[] data, boolean compatibilityMode) throws DecryptionException {
        return engine.decrypt(key, data, compatibilityMode);
    }

    public static AESKey readAESKey(byte[] rawEncodedKey) throws InvalidKeyException {
        return engine.readAESKey(rawEncodedKey);
    }

    public static void setDefaultCompatibilityMode(boolean defaultCompatibilityMode) {
        engine.setDefaultCompatibilityMode(defaultCompatibilityMode);
    }

    public static byte[] sign(@NotNull SigningKey key, @Nullable DigestAlgorithm digestAlgorithms, @NotNull byte[] data) throws InvalidKeyException {
        return engine.sign(key, digestAlgorithms, data);
    }

    public static byte[] encrypt(@NotNull EncryptionKey key, @NotNull byte[] data, boolean compatibilityMode) throws EncryptionException {
        return engine.encrypt(key, data, compatibilityMode);
    }

    public static RSAKeyPair readRSAKeyPair(byte[] customEncodedKey) throws InvalidKeyException {
        return engine.readRSAKeyPair(customEncodedKey);
    }

    @NotNull
    public static RSAKeyPair generateRSAKeyPair(int keySize) {
        return engine.generateRSAKeyPair(keySize);
    }

    public static byte[] sign(@NotNull SigningKey key, @NotNull byte[] data) throws InvalidKeyException {
        return engine.sign(key, data);
    }

    @NotNull
    public static <K extends Key> K generateKey(@NotNull Class<K> keyType, int keySize) {
        return engine.generateKey(keyType, keySize);
    }

    @NotNull
    public static AESKey generatePBEAESKey(DigestAlgorithm digestAlgorithm, char[] key, int iterations, byte[] salt, AESKeyLen keyLen) {
        return engine.generatePBEAESKey(digestAlgorithm, key, iterations, salt, keyLen);
    }

    @NotNull
    public static HMACKey generatePBEHMACKey(DigestAlgorithm pbkdf2DigestAlgorithm, DigestAlgorithm hmacDigestAlgorithm, char[] password, int iterations, byte[] salt) {
        return engine.generatePBEHMACKey(pbkdf2DigestAlgorithm, hmacDigestAlgorithm, password, iterations, salt);
    }

    public static byte[] digest(byte[] data, DigestAlgorithm alg) {
        return engine.digest(data, alg);
    }

    public static byte[] rsaSign(@NotNull byte[] pkcs8encodedPrivateKey, @NotNull DigestAlgorithm digestAlgorithms, @NotNull byte[] data) throws InvalidKeyException {
        return engine.rsaSign(pkcs8encodedPrivateKey, digestAlgorithms, data);
    }

    public static byte[] decrypt(@NotNull DecryptionKey key, @NotNull byte[] data, String cipherAlgorithm) throws DecryptionException {
        return engine.decrypt(key, data, cipherAlgorithm);
    }

    public static byte[] rsaEncrypt(@NotNull byte[] x509encodedPublicKey, @NotNull SymmetricAlgorithm symmetricAlgorithm, int symmetricKeySize, @NotNull byte[] data) throws EncryptionException {
        return engine.rsaEncrypt(x509encodedPublicKey, symmetricAlgorithm, symmetricKeySize, data);
    }

    public static HMACKey readHMACKey(DigestAlgorithm digestAlgorithm, byte[] rawEncodedKey) throws InvalidKeyException {
        return engine.readHMACKey(digestAlgorithm, rawEncodedKey);
    }

    public static void rsaVerifySignature(@NotNull byte[] x509encodedPrivateKey, @NotNull DigestAlgorithm digestAlgorithms, @NotNull byte[] data, @NotNull byte[] signature) throws SignatureException, InvalidKeyException {
        engine.rsaVerifySignature(x509encodedPrivateKey, digestAlgorithms, data, signature);
    }

    public static boolean isTestEngine() {
        return engine.isTestEngine();
    }

    public static class DataAndSalt {
        private byte[] data;
        private byte[] salt;

        public DataAndSalt(byte[] data, byte[] salt) {
            this.data = data;
            this.salt = salt;
        }

        public byte[] getData() {
            return data;
        }

        public byte[] getSalt() {
            return salt;
        }
    }
}
