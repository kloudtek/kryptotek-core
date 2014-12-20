/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek;

import com.kloudtek.kryptotek.key.jce.*;
import com.kloudtek.util.UnexpectedException;
import com.kloudtek.util.io.ByteArrayDataInputStream;
import com.kloudtek.util.io.ByteArrayDataOutputStream;
import org.jetbrains.annotations.NotNull;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * Cryptography provider that uses the standard java crypto extension (JCE)
 */
public class JCECryptoEngine extends CryptoEngine {
    public static final String S_RSA = "RSA";
    public static final String S_AES = "AES";
    public static final String AES_CBC_PKCS_5_PADDING = "AES/ECB/PKCS5PADDING";
    public static final String RSA_ECB_OAEPPADDING = "RSA/ECB/OAEPWithSHA1AndMGF1Padding";
    public static final String RSA_ECB_PKCS1_PADDING = "RSA/ECB/PKCS1Padding";

    public static String getRSAEncryptionAlgorithm(boolean compatibilityMode) {
        return compatibilityMode ? RSA_ECB_PKCS1_PADDING : RSA_ECB_OAEPPADDING;
    }

    // New crypto abstraction API

    /**
     * Generate a crypto key of the specified type
     *
     * @param type    Key type (must be a valid type, for example it's not possible create an X509 certificate using this API)
     * @param keySize key size (this is ignored in the case of HMAC keys since the type specifies the length)
     * @return new key
     * @throws IllegalArgumentException If the type or keySize are invalid
     */
    @Override
    public Key generateKey(Key.Type type, int keySize) {
        try {
            switch (type) {
                case AES:
                    KeyGenerator aesKeyGen = KeyGenerator.getInstance(SymmetricAlgorithm.AES.getJceId());
                    aesKeyGen.init(keySize);
                    return new JCEAESKey(aesKeyGen.generateKey());
                case HMAC_SHA1:
                    return new JCEHMACKey(type, KeyGenerator.getInstance("HmacSHA1").generateKey());
                case HMAC_SHA256:
                    return new JCEHMACKey(type, KeyGenerator.getInstance("HmacSHA256").generateKey());
                case HMAC_SHA512:
                    return new JCEHMACKey(type, KeyGenerator.getInstance("HmacSHA512").generateKey());
                case RSA_KEYPAIR:
                    KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance(AsymmetricAlgorithm.RSA.getJceId());
                    rsaKeyGen.initialize(keySize);
                    return new JCERSAKeyPair(rsaKeyGen.generateKeyPair());
                default:
                    throw new IllegalArgumentException("Cannot create a key of type " + type);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedException(e);
        }
    }

    @Override
    public Key readKey(@NotNull byte[] encodedKey, @NotNull Key.Type type) throws InvalidKeyException {
        switch (type) {
            case AES:
            case HMAC_SHA1:
            case HMAC_SHA256:
            case HMAC_SHA512:
                return readKey(new EncodedKey(encodedKey, EncodedKey.Format.RAW), type);
            case RSA_PRIVATE:
                return readKey(EncodedKey.rsaPrivatePkcs8(encodedKey), type);
            case RSA_PUBLIC:
                return readKey(EncodedKey.rsaPublicX509(encodedKey), type);
            default:
                throw new InvalidKeyException("Unsupported key type " + type);
        }
    }

    @Override
    public Key readKey(@NotNull EncodedKey encodedKey, @NotNull Key.Type type) throws InvalidKeyException {
        try {
            byte[] encodedKeyData = encodedKey.getEncodedKey();
            switch (type) {
                case AES:
                    return new JCEAESKey(new SecretKeySpec(encodedKeyData, "AES"));
                case HMAC_SHA1:
                    return new JCEHMACKey(type, new SecretKeySpec(encodedKeyData, "HmacSHA1"));
                case HMAC_SHA256:
                    return new JCEHMACKey(type, new SecretKeySpec(encodedKeyData, "HmacSHA256"));
                case HMAC_SHA512:
                    return new JCEHMACKey(type, new SecretKeySpec(encodedKeyData, "HmacSHA512"));
                case RSA_PRIVATE:
                    PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(encodedKeyData);
                    return new JCERSAPrivateKey(KeyFactory.getInstance(S_RSA).generatePrivate(privKeySpec));
                case RSA_PUBLIC:
                    X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encodedKeyData);
                    return new JCERSAPublicKey(KeyFactory.getInstance(S_RSA).generatePublic(pubKeySpec));
                default:
                    throw new InvalidKeyException("Unsupported key type " + type);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedException(e);
        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException(e);
        }
    }

    @Override
    public byte[] encrypt(@NotNull Key key, @NotNull byte[] data, boolean compatibilityMode) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return crypt(key, data, true, compatibilityMode);
    }

    @Override
    public byte[] encrypt(@NotNull Key key, @NotNull SymmetricAlgorithm symmetricAlgorithm, int symmetricKeySize, @NotNull byte[] data, boolean compatibilityMode) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        checkJceKey(key);
        ByteArrayDataOutputStream buf = new ByteArrayDataOutputStream();
        try {
            try {
                byte[] encryptedData = crypt(key, data, true, compatibilityMode);
                buf.writeShort(0);
                buf.write(encryptedData);
            } catch (IllegalBlockSizeException e) {
                Key sKey = generateKey(symmetricAlgorithm.getKeyType(), symmetricKeySize);
                byte[] encryptedSecretKey = encrypt(key, sKey.getEncoded().getEncodedKey(), compatibilityMode);
                buf.writeShort(encryptedSecretKey.length);
                buf.write(encryptedSecretKey);
                buf.write(encrypt(sKey, data, compatibilityMode));
                sKey.destroy();
            }
        } catch (IOException e) {
            throw new UnexpectedException(e);
        }
        return buf.toByteArray();
    }

    @Override
    public byte[] decrypt(@NotNull Key key, @NotNull byte[] data, boolean compatibilityMode) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return crypt(key, data, false, compatibilityMode);
    }

    @Override
    public byte[] decrypt(@NotNull Key key, @NotNull SymmetricAlgorithm symmetricAlgorithm, int symmetricKeySize, @NotNull byte[] data, boolean compatibilityMode) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        checkJceKey(key);
        if (data.length < 3) {
            throw new IllegalArgumentException("Encrypted data is invalid");
        }
        try {
            ByteArrayDataInputStream is = new ByteArrayDataInputStream(data);
            short skeyLen = is.readShort();
            if (skeyLen <= 0) {
                byte[] encryptedData = is.readFully(data.length - 2);
                return crypt(key, encryptedData, false, compatibilityMode);
            } else {
                byte[] encodedSKeyData = is.readFully(skeyLen);
                byte[] encodedSKey = crypt(key, encodedSKeyData, false, compatibilityMode);
                byte[] encryptedData = is.readFully(data.length - 2 - skeyLen);
                Key sKey = readKey(encodedSKey, symmetricAlgorithm.getKeyType());
                return crypt(sKey, encryptedData, false, compatibilityMode);
            }
        } catch (IOException e) {
            throw new IllegalArgumentException("Encrypted data is invalid");
        }
    }

    private byte[] crypt(Key key, byte[] data, boolean encryptMode, boolean compatibilityMode) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        try {
            checkJceKey(key);
            String jceCryptAlgorithm = ((JCEKey) key).getJceCryptAlgorithm(compatibilityMode);
            if (jceCryptAlgorithm == null) {
                throw new IllegalArgumentException("Unable to perform de/encryption operation using key of type " + key.getAlgorithm());
            }
            if (key instanceof JCESecretKey) {
                return crypt(jceCryptAlgorithm, ((JCESecretKey) key).getSecretKey(), data, encryptMode);
            } else if (key instanceof JCEKeyPair) {
                KeyPair keyPair = ((JCEKeyPair) key).getKeyPair();
                return crypt(jceCryptAlgorithm, encryptMode ? keyPair.getPublic() : keyPair.getPrivate(), data, encryptMode);
            } else if (key instanceof JCEPublicKey) {
                return crypt(jceCryptAlgorithm, ((JCEPublicKey) key).getPublicKey(), data, encryptMode);
            } else {
                throw new IllegalArgumentException("Unable to perform de/encryption operation using key of type " + key.getAlgorithm());
            }
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedException(e);
        } catch (NoSuchPaddingException e) {
            throw new UnexpectedException(e);
        }
    }

    private PublicKey getPublicKey(Key key) {
        if (key instanceof JCEPublicKey) {
            return ((JCEPublicKey) key).getPublicKey();
        } else if (key instanceof JCEKeyPair) {
            return ((JCEKeyPair) key).getKeyPair().getPublic();
        } else {
            return null;
        }
    }

    private PrivateKey getPrivateKey(Key key) {
        if (key instanceof JCEPrivateKey) {
            return ((JCEPrivateKey) key).getPrivateKey();
        } else if (key instanceof JCEKeyPair) {
            return ((JCEKeyPair) key).getKeyPair().getPrivate();
        } else {
            return null;
        }
    }


    private byte[] crypt(String algorithm, java.security.Key key, byte[] data, boolean encrypt) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    @Override
    public byte[] sign(Key key, byte[] data) throws SignatureException, InvalidKeyException {
        try {
            checkJceKey(key);
            switch (key.getType()) {
                case HMAC_SHA1:
                case HMAC_SHA256:
                case HMAC_SHA512:
                    Mac mac = Mac.getInstance("Hmac" + key.getAlgorithm().name());
                    mac.init(((JCEHMACKey) key).getSecretKey());
                    return mac.doFinal(data);
                case RSA_PRIVATE:
                    return sign(key, DigestAlgorithm.SHA256, data);
                default:
                    if (key.isSigningKey()) {
                        throw new IllegalArgumentException("Unsupported signing key: " + key.getType());
                    } else {
                        throw new IllegalArgumentException("Key is not a signing key: " + key.getType());
                    }
            }
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedException(e);
        }
    }

    @Override
    public byte[] sign(@NotNull Key key, @NotNull DigestAlgorithm digestAlgorithms, @NotNull byte[] data) throws SignatureException, InvalidKeyException {
        try {
            checkJceKey(key);
            PrivateKey privateKey = getPrivateKey(key);
            if (privateKey != null && privateKey instanceof java.security.interfaces.RSAPrivateKey) {
                Signature signature = Signature.getInstance(digestAlgorithms.name() + "withRSA");
                signature.initSign(privateKey);
                signature.update(data);
                return signature.sign();
            } else {
                throw new IllegalArgumentException("Unable to sign using key type " + key.getType() + " with digest " + digestAlgorithms.name());
            }
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedException(e);
        }
    }

    @Override
    public void verifySignature(@NotNull Key key, @NotNull byte[] data, @NotNull byte[] signature) throws SignatureException, InvalidKeyException {
        checkJceKey(key);
        switch (key.getType()) {
            case HMAC_SHA1:
            case HMAC_SHA256:
            case HMAC_SHA512:
                if (!Arrays.equals(sign(key, data), signature)) {
                    throw new SignatureException("Signature does not match data");
                }
                break;
            case RSA_PUBLIC:
                verifySignature(key, DigestAlgorithm.SHA256, data, signature);
        }
    }

    @Override
    public void verifySignature(@NotNull Key key, @NotNull DigestAlgorithm digestAlgorithms, @NotNull byte[] data, @NotNull byte[] signature) throws SignatureException, InvalidKeyException {
        try {
            PublicKey publicKey = getPublicKey(key);
            if (publicKey != null && publicKey instanceof java.security.interfaces.RSAPublicKey) {
                Signature sig = Signature.getInstance(digestAlgorithms.name() + "withRSA");
                sig.initVerify(publicKey);
                sig.update(data);
                if (!sig.verify(signature)) {
                    throw new SignatureException();
                }
            } else {
                throw new IllegalArgumentException("Unable to sign using key type " + key.getType() + " with digest " + digestAlgorithms.name());
            }
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedException(e);
        }
    }

    @Override
    public SecretKey generatePBEAESKey(char[] password, int iterations, byte[] salt, int keyLen) throws InvalidKeySpecException {
        try {
            KeySpec keySpec = new PBEKeySpec(password, salt, iterations, keyLen);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            return new SecretKeySpec(keyFactory.generateSecret(keySpec).getEncoded(), "AES");
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedException(e);
        }
    }

    @Override
    public byte[] digest(byte[] data, DigestAlgorithm alg) {
        try {
            MessageDigest sha = MessageDigest.getInstance(alg.getJceId());
            sha.update(data);
            return sha.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedException(e);
        }
    }

    @Override
    public Digest digest(DigestAlgorithm alg) {
        try {
            return new JCEDigest(MessageDigest.getInstance(alg.getJceId()));
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedException(e);
        }
    }

    private void checkJceKey(Key key) {
        if (!(key instanceof JCEKey)) {
            throw new IllegalArgumentException("Key must be a JCE key");
        }
    }

    // Key generation

    /**
     * Generate a private key using a symmetric algorithm
     *
     * @param alg     Symmetric algorithm
     * @param keysize Key size
     * @return secret key
     */
    @Override
    public SecretKey generateSecretKey(SymmetricAlgorithm alg, int keysize) {
        try {
            KeyGenerator kg = KeyGenerator.getInstance(alg.getJceId());
            kg.init(keysize);
            return kg.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Generate an HMAC key
     *
     * @param algorithm digest algorithm
     * @return secret key
     */
    @Override
    public SecretKey generateHmacKey(DigestAlgorithm algorithm) {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("Hmac" + algorithm.name());
            return kg.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public KeyPair generateKeyPair(AsymmetricAlgorithm alg, int keySize) {
        try {
            KeyPairGenerator kg = KeyPairGenerator.getInstance(alg.getJceId());
            kg.initialize(keySize);
            return kg.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Read an X509 Encoded S_RSA public key
     *
     * @param key X509 encoded rsa key
     * @return Public key object
     * @throws java.security.spec.InvalidKeySpecException If the key is invalid
     */
    @Override
    public java.security.interfaces.RSAPublicKey readRSAPublicKey(@NotNull byte[] key) throws InvalidKeySpecException {
        PublicKey result;
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(S_RSA);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(key);
            result = keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedException(e);
        }
        return (java.security.interfaces.RSAPublicKey) result;
    }

    /**
     * Read a PKCS8 Encoded S_RSA private key
     *
     * @param encodedPriKey PKCS8 encoded rsa key
     * @return Public key object
     * @throws InvalidKeySpecException If the key is invalid
     */
    @Override
    public PrivateKey readRSAPrivateKey(@NotNull byte[] encodedPriKey) throws InvalidKeySpecException {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(S_RSA);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedPriKey);
            return keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedException(e);
        }
    }

    @Override
    public SecretKey readAESKey(@NotNull byte[] encodedAesKey) {
        return new SecretKeySpec(encodedAesKey, "AES");
    }

    @Override
    public SecretKey readHMACKey(@NotNull DigestAlgorithm algorithm, @NotNull byte[] encodedKey) {
        return new SecretKeySpec(encodedKey, "Hmac" + algorithm.getJceId());
    }

    // HMAC

    @Override
    public byte[] hmac(DigestAlgorithm algorithm, SecretKey key, byte[] data) throws InvalidKeyException {
        try {
            Mac mac = Mac.getInstance("Hmac" + algorithm.name());
            mac.init(key);
            return mac.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedException(e);
        }
    }

    @Override
    public byte[] hmacSha1(SecretKey key, byte[] data) throws InvalidKeyException {
        return hmac(DigestAlgorithm.SHA1, key, data);
    }

    @Override
    public byte[] hmacSha256(SecretKey key, byte[] data) throws InvalidKeyException {
        return hmac(DigestAlgorithm.SHA256, key, data);
    }

    @Override
    public byte[] hmacSha512(SecretKey key, byte[] data) throws InvalidKeyException {
        return hmac(DigestAlgorithm.SHA512, key, data);
    }

    // AES encryption

    @Override
    public byte[] aesEncrypt(byte[] key, byte[] data) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return aesEncrypt(new SecretKeySpec(key, 0, key.length, S_AES), data);
    }

    @Override
    public byte[] aesEncrypt(SecretKey key, byte[] data) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return encrypt(key, data, AES_CBC_PKCS_5_PADDING);
    }

    @Override
    public byte[] aesDecrypt(byte[] key, byte[] data) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return aesDecrypt(new SecretKeySpec(key, 0, key.length, S_AES), data);
    }

    @Override
    public byte[] aesDecrypt(SecretKey key, byte[] data) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return decrypt(key, data, AES_CBC_PKCS_5_PADDING);
    }

    // RSA Encryption and signing

    @Override
    public byte[] rsaEncrypt(byte[] key, byte[] data) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {
        return rsaEncrypt(readRSAPublicKey(key), data);
    }

    @Override
    public byte[] rsaEncrypt(PublicKey key, byte[] data) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return encrypt(key, data, RSA_ECB_OAEPPADDING);
    }

    @Override
    public byte[] rsaDecrypt(byte[] key, byte[] data) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {
        return rsaDecrypt(readRSAPrivateKey(key), data);
    }

    @Override
    public byte[] rsaDecrypt(PrivateKey key, byte[] data) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return decrypt(key, data, RSA_ECB_OAEPPADDING);
    }

    @Override
    public byte[] rsaSign(DigestAlgorithm digestAlgorithms, PrivateKey key, byte[] data) throws InvalidKeyException, SignatureException {
        return sign(digestAlgorithms.name() + "withRSA", key, data);
    }

    @Override
    public void rsaVerifySignature(DigestAlgorithm digestAlgorithms, PublicKey key, byte[] data, byte[] signature) throws InvalidKeyException, SignatureException {
        verifySignature(digestAlgorithms.name() + "withRSA", key, data, signature);
    }

    // Basic encryption / signing methods

    @Override
    public byte[] encrypt(java.security.Key key, byte[] data, String alg) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return crypt(key, data, alg, Cipher.ENCRYPT_MODE);
    }

    @Override
    public byte[] decrypt(java.security.Key key, byte[] data, String alg) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return crypt(key, data, alg, Cipher.DECRYPT_MODE);
    }

    @Override
    public byte[] crypt(java.security.Key key, byte[] data, String alg, int mode) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        try {
            Cipher aesCipher = Cipher.getInstance(alg);
            aesCipher.init(mode, key);
            return aesCipher.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedException(e);
        } catch (NoSuchPaddingException e) {
            throw new UnexpectedException(e);
        }
    }

    @Override
    public byte[] sign(String algorithm, PrivateKey key, byte[] data) throws SignatureException, InvalidKeyException {
        try {
            Signature signature = Signature.getInstance(algorithm);
            signature.initSign(key);
            signature.update(data);
            return signature.sign();
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedException(e);
        }
    }

    @Override
    public void verifySignature(String algorithm, PublicKey key, byte[] data, byte[] signature) throws SignatureException, InvalidKeyException {
        try {
            Signature sig = Signature.getInstance(algorithm);
            sig.initVerify(key);
            sig.update(data);
            if (!sig.verify(signature)) {
                throw new SignatureException();
            }
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedException(e);
        }
    }

}
