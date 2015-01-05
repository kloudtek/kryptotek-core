/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek;

import com.kloudtek.kryptotek.key.*;
import com.kloudtek.kryptotek.key.jce.*;
import com.kloudtek.util.UnexpectedException;
import com.kloudtek.util.io.ByteArrayDataInputStream;
import com.kloudtek.util.io.ByteArrayDataOutputStream;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

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

import static com.kloudtek.kryptotek.EncodedKey.Format.*;

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
     * @param keyType Key type (must be a valid type, for example it's not possible create an X509 certificate using this API)
     * @param keySize key size (this is ignored in the case of HMAC keys since the type specifies the length)
     * @return new key
     * @throws IllegalArgumentException If the type or keySize are invalid
     */
    @Override
    public <K extends Key> K generateKey(@NotNull Class<K> keyType, int keySize) {
        try {
            if (AESKey.class.isAssignableFrom(keyType)) {
                KeyGenerator aesKeyGen = KeyGenerator.getInstance(SymmetricAlgorithm.AES.getJceId());
                aesKeyGen.init(keySize);
                return keyType.cast(new JCEAESKey(this,aesKeyGen.generateKey()));
            } else if (HMACSHA1Key.class.isAssignableFrom(keyType)) {
                return keyType.cast(new JCEHMACSHA1Key(this,KeyGenerator.getInstance("HmacSHA1").generateKey()));
            } else if (HMACSHA256Key.class.isAssignableFrom(keyType)) {
                return keyType.cast(new JCEHMACSHA256Key(this,KeyGenerator.getInstance("HmacSHA1").generateKey()));
            } else if (HMACSHA512Key.class.isAssignableFrom(keyType)) {
                return keyType.cast(new JCEHMACSHA512Key(this,KeyGenerator.getInstance("HmacSHA1").generateKey()));
            } else if (RSAKeyPair.class.isAssignableFrom(keyType)) {
                KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance(AsymmetricAlgorithm.RSA.getJceId());
                rsaKeyGen.initialize(keySize);
                return keyType.cast(new JCERSAKeyPair(this,rsaKeyGen.generateKeyPair()));
            } else {
                throw new IllegalArgumentException("Cannot create a key of type " + keyType.getName());
            }
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedException(e);
        }
    }

    @Override
    public <K extends Key> K readKey(@NotNull Class<K> keyType, @NotNull EncodedKey encodedKey) throws InvalidKeyException {
        byte[] encodedKeyData = encodedKey.getEncodedKey();
        try {
            if (AESKey.class.isAssignableFrom(keyType) && encodedKey.getFormat() == RAW) {
                return keyType.cast(new JCEAESKey(this,encodedKeyData));
            } else if (HMACSHA1Key.class.isAssignableFrom(keyType) && ( encodedKey.getFormat() == RAW || encodedKey.getFormat() == SERIALIZED ) ) {
                return keyType.cast(new JCEHMACSHA1Key(this,encodedKeyData));
            } else if (HMACSHA256Key.class.isAssignableFrom(keyType) && ( encodedKey.getFormat() == RAW || encodedKey.getFormat() == SERIALIZED ) ) {
                return keyType.cast(new JCEHMACSHA256Key(this,encodedKeyData));
            } else if (HMACSHA512Key.class.isAssignableFrom(keyType) && ( encodedKey.getFormat() == RAW || encodedKey.getFormat() == SERIALIZED ) ) {
                return keyType.cast(new JCEHMACSHA512Key(this,encodedKeyData));
            } else if (RSAPrivateKey.class.isAssignableFrom(keyType) && ( encodedKey.getFormat() == PKCS8 || encodedKey.getFormat() == SERIALIZED ) ) {
                return keyType.cast(new JCERSAPrivateKey(this,KeyFactory.getInstance("RSA")
                        .generatePrivate(new PKCS8EncodedKeySpec(encodedKeyData))));
            } else if (RSAPublicKey.class.isAssignableFrom(keyType) && ( encodedKey.getFormat() == X509 || encodedKey.getFormat() == SERIALIZED ) ) {
                return keyType.cast(new JCERSAPublicKey(this,KeyFactory.getInstance("RSA")
                        .generatePublic(new X509EncodedKeySpec(encodedKeyData))));
            } else if (RSAKeyPair.class.isAssignableFrom(keyType) && encodedKey.getFormat() == SERIALIZED) {
                return keyType.cast(new JCERSAKeyPair(this,encodedKeyData));
            } else {
                throw new InvalidKeyException("Unsupported key type " + keyType.getName() + " and format " + encodedKey.getFormat().name());
            }
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedException(e);
        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException(e);
        }
    }

    @Override
    public <K extends Key> K readKey(@NotNull Class<K> keyType, @NotNull byte[] encodedKey) throws InvalidKeyException {
        if (AESKey.class.isAssignableFrom(keyType) || HMACKey.class.isAssignableFrom(keyType)) {
            return readKey(keyType, new EncodedKey(encodedKey, RAW));
        } else if (RSAPrivateKey.class.isAssignableFrom(keyType)) {
            return readKey(keyType, EncodedKey.rsaPrivatePkcs8(encodedKey));
        } else if (RSAPublicKey.class.isAssignableFrom(keyType)) {
            return readKey(keyType, EncodedKey.rsaPublicX509(encodedKey));
        } else if (RSAKeyPair.class.isAssignableFrom(keyType)) {
            return readKey(keyType, new EncodedKey(encodedKey, EncodedKey.Format.SERIALIZED));
        } else {
            throw new InvalidKeyException("Unsupported key type " + keyType.getName());
        }
    }

    @Override
    public byte[] encrypt(@NotNull EncryptionKey key, @NotNull byte[] data, boolean compatibilityMode) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return crypt(key, data, true, compatibilityMode);
    }

    @Override
    public byte[] encrypt(@NotNull EncryptionKey key, @NotNull SymmetricAlgorithm symmetricAlgorithm, int symmetricKeySize, @NotNull byte[] data, boolean compatibilityMode) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        checkJceKey(key);
        ByteArrayDataOutputStream buf = new ByteArrayDataOutputStream();
        try {
            try {
                byte[] encryptedData = crypt(key, data, true, compatibilityMode);
                buf.writeShort(0);
                buf.write(encryptedData);
            } catch (IllegalBlockSizeException e) {
                AESKey sKey = generateKey(AESKey.class, symmetricKeySize);
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
    public byte[] decrypt(@NotNull DecryptionKey key, @NotNull byte[] data, boolean compatibilityMode) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return crypt(key, data, false, compatibilityMode);
    }

    @Override
    public byte[] decrypt(@NotNull DecryptionKey key, @NotNull SymmetricAlgorithm symmetricAlgorithm, int symmetricKeySize, @NotNull byte[] data, boolean compatibilityMode) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
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
                Key sKey = readKey(symmetricAlgorithm.getKeyClass(), encodedSKey);
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
                throw new IllegalArgumentException("Unable to perform de/encryption operation using key of type " + key.getClass().getName());
            }
            if (key instanceof JCESecretKey) {
                return crypt(jceCryptAlgorithm, ((JCESecretKey) key).getSecretKey(), data, encryptMode);
            } else if (key instanceof JCEKeyPair) {
                java.security.KeyPair keyPair = ((JCEKeyPair) key).getJCEKeyPair();
                return crypt(jceCryptAlgorithm, encryptMode ? keyPair.getPublic() : keyPair.getPrivate(), data, encryptMode);
            } else if (key instanceof JCEPublicKey) {
                return crypt(jceCryptAlgorithm, ((JCEPublicKey) key).getPublicKey(), data, encryptMode);
            } else {
                throw new IllegalArgumentException("Unable to perform de/encryption operation using key of type " + key.getClass().getName());
            }
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedException(e);
        } catch (NoSuchPaddingException e) {
            throw new UnexpectedException(e);
        }
    }

    private byte[] crypt(String algorithm, java.security.Key key, byte[] data, boolean encrypt) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    @Override
    public byte[] sign(@NotNull SigningKey key, @Nullable DigestAlgorithm digestAlgorithm, @NotNull byte[] data) throws InvalidKeyException {
        try {
            if (key instanceof JCERSAKeyPair) {
                if (digestAlgorithm == null) {
                    digestAlgorithm = DigestAlgorithm.SHA256;
                }
                RSAPrivateKey rsaPrivateKey = getRSAPrivateKey(key);
                if (rsaPrivateKey != null) {
                    Signature signature = Signature.getInstance(digestAlgorithm.name() + "withRSA");
                    signature.initSign(((JCERSAPrivateKey) rsaPrivateKey).getJCEPrivateKey());
                    signature.update(data);
                    return signature.sign();
                }
            } else if (key instanceof JCEHMACKey) {
                Mac mac = Mac.getInstance("Hmac" + ((JCEHMACKey) key).getDigestAlgorithm().name());
                mac.init(((JCEHMACKey) key).getSecretKey());
                return mac.doFinal(data);
            }
            throw new IllegalArgumentException("Unable to sign using key type " + key.getClass().getName() + " with digest " + digestAlgorithm.name());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Unable to sign using key type " + key.getClass().getName() + " with digest " + digestAlgorithm.name());
        } catch (SignatureException e) {
            throw new InvalidKeyException(e);
        }
    }

    @Override
    public void verifySignature(@NotNull SignatureVerificationKey key, @Nullable DigestAlgorithm digestAlgorithm, @NotNull byte[] data, @NotNull byte[] signature) throws SignatureException, InvalidKeyException {
        try {
            if (key instanceof JCEHMACKey) {
                Mac mac = Mac.getInstance("Hmac" + ((JCEHMACKey) key).getDigestAlgorithm().name());
                mac.init(((JCEHMACKey) key).getSecretKey());
                if (!Arrays.equals(mac.doFinal(data), signature)) {
                    throw new SignatureException("Signature does not match data");
                }
            } else if (key instanceof JCERSAKey) {
                if (digestAlgorithm == null) {
                    digestAlgorithm = DigestAlgorithm.SHA256;
                }
                JCERSAPublicKey publicKey = getRSAPublicKey(key);
                if (publicKey != null) {
                    Signature sig = Signature.getInstance(digestAlgorithm.name() + "withRSA");
                    sig.initVerify(publicKey.getPublicKey());
                    sig.update(data);
                    if (!sig.verify(signature)) {
                        throw new SignatureException();
                    }
                }
            } else {
                throw new IllegalArgumentException("Unable to sign using key type " + key.getClass().getName() + " with digest " + digestAlgorithm.name());
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

    private JCERSAPublicKey getRSAPublicKey(Key key) {
        if (key instanceof JCERSAPublicKey) {
            return (JCERSAPublicKey) key;
        } else if (key instanceof JCEKeyPair) {
            return new JCERSAPublicKey(this,((JCEKeyPair) key).getJCEKeyPair().getPublic());
        } else {
            return null;
        }
    }

    private JCERSAPrivateKey getRSAPrivateKey(Key key) {
        if (key instanceof JCERSAPrivateKey) {
            return (JCERSAPrivateKey) key;
        } else if (key instanceof JCEKeyPair) {
            return new JCERSAPrivateKey(this,((JCEKeyPair) key).getJCEKeyPair().getPrivate());
        } else {
            return null;
        }
    }

    private void checkJceKey(Key key) {
        if (!(key instanceof JCEKey)) {
            throw new IllegalArgumentException("Key must be a JCE key");
        }
    }
}
