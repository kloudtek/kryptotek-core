/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.jce;

import com.kloudtek.kryptotek.*;
import com.kloudtek.kryptotek.key.*;
import com.kloudtek.kryptotek.key.PublicKey;
import com.kloudtek.ktserializer.InvalidSerializedDataException;
import com.kloudtek.ktserializer.Serializer;
import com.kloudtek.ktserializer.SimpleClassMapper;
import com.kloudtek.util.ArrayUtils;
import com.kloudtek.util.StringUtils;
import com.kloudtek.util.UnexpectedException;
import com.kloudtek.util.io.ByteArrayDataInputStream;
import com.kloudtek.util.io.ByteArrayDataOutputStream;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.crypto.*;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;

import static com.kloudtek.kryptotek.EncodedKey.Format.*;

/**
 * Cryptography provider that uses the standard java crypto extension (JCE)
 */
public class JCECryptoEngine extends CryptoEngine {
    private static final SimpleClassMapper classMapper = new SimpleClassMapper(JCEAESKey.class, JCEHMACSHA1Key.class,
            JCEHMACSHA256Key.class, JCEHMACSHA512Key.class, JCERSAPrivateKey.class, JCERSAPublicKey.class, JCERSAKeyPair.class,
            JCESimpleCertificate.class, JCEDHKeyPair.class, JCEDHPrivateKey.class, JCEDHPublicKey.class);
    final Serializer serializer = new Serializer(classMapper).setInject(CryptoEngine.class, this);

    public static String getRSAEncryptionAlgorithm(boolean compatibilityMode) {
        return compatibilityMode ? RSA_ECB_PKCS1_PADDING : RSA_ECB_OAEPPADDING;
    }

    // New crypto abstraction API

    @NotNull
    @Override
    public AESKey generateAESKey(int keySize) {
        try {
            KeyGenerator aesKeyGen = KeyGenerator.getInstance(SymmetricAlgorithm.AES.getJceId());
            aesKeyGen.init(keySize);
            return new JCEAESKey(this, aesKeyGen.generateKey());
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedException(e);
        }
    }

    @NotNull
    @Override
    public AESKey generateAESKey(int keySize, DHPrivateKey dhPrivateKey, DHPublicKey dhPublicKey) throws InvalidKeyException {
        final byte[] keyData = agreeDHKey(dhPrivateKey, dhPublicKey);
        return generatePBEAESKey(StringUtils.base64Encode(keyData).toCharArray(),10,Arrays.copyOf(keyData,keyData.length > 30 ? 30 : keyData.length),keySize);
    }

    @NotNull
    @Override
    public HMACKey generateHMACKey(DigestAlgorithm digestAlgorithm) {
        try {
            SecretKey secretKey = KeyGenerator.getInstance("Hmac" + digestAlgorithm.name()).generateKey();
            return createHmacKey(digestAlgorithm, secretKey);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Cannot create an hmac key of type Hmac" + digestAlgorithm.name());
        }
    }

    @NotNull
    @Override
    public HMACKey generateHMACKey(DigestAlgorithm digestAlgorithm, DHPrivateKey dhPrivateKey, DHPublicKey dhPublicKey) throws InvalidKeyException {
        final byte[] keyData = agreeDHKey(dhPrivateKey, dhPublicKey);
        return createHmacKey(digestAlgorithm, new SecretKeySpec(keyData, "HMAC"));
    }

    @NotNull
    @Override
    public RSAKeyPair generateRSAKeyPair(int keySize) {
        try {
            KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance(AsymmetricAlgorithm.RSA.getJceId());
            rsaKeyGen.initialize(keySize);
            return new JCERSAKeyPair(this, rsaKeyGen.generateKeyPair());
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedException(e);
        }
    }

    @NotNull
    @Override
    public SimpleCertificate generateSimpleCertificate(String subject, PublicKey publicKey) {
        return new JCESimpleCertificate(this, subject, publicKey);
    }

    @NotNull
    @Override
    public DHParameters generateDHParameters(int keySize) {
        try {
            AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
            paramGen.init(keySize, CryptoUtils.rng());
            AlgorithmParameters params = paramGen.generateParameters();
            DHParameterSpec dhSpec = params.getParameterSpec(DHParameterSpec.class);
            return new DHParameters(dhSpec.getP(),dhSpec.getG(),dhSpec.getL());
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedException(e);
        } catch (InvalidParameterSpecException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @NotNull
    @Override
    public DHKeyPair generateDHKeyPair(DHParameters parameterSpec) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DiffieHellman");
            DHParameterSpec param = new DHParameterSpec(parameterSpec.getP(), parameterSpec.getG(), parameterSpec.getL());
            kpg.initialize(param);
            return new JCEDHKeyPair(this, kpg.generateKeyPair());
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public com.kloudtek.kryptotek.Key readSerializedKey(byte[] serializedKey) throws InvalidKeyException {
        if (serializedKey.length < 1 || serializedKey[0] < 0) {
            throw new InvalidKeyException();
        }
        try {
            return serializer.deserialize(com.kloudtek.kryptotek.Key.class, serializedKey);
        } catch (InvalidSerializedDataException e) {
            throw new InvalidKeyException(e);
        }
    }

    @Override
    public <K extends com.kloudtek.kryptotek.Key> K readKey(@NotNull Class<K> keyType, @NotNull EncodedKey encodedKey) throws InvalidKeyException {
        byte[] encodedKeyData = encodedKey.getEncodedKey();
        if (encodedKey.getFormat() == SERIALIZED) {
            com.kloudtek.kryptotek.Key deserializedKey = readSerializedKey(encodedKeyData);
            if (keyType.isInstance(deserializedKey)) {
                return keyType.cast(deserializedKey);
            } else {
                throw new InvalidKeyException("Key " + deserializedKey.getClass().getName() + " does not match expected " + keyType.getName());
            }
        } else {
            try {
                if (AESKey.class.isAssignableFrom(keyType) && encodedKey.getFormat() == RAW) {
                    return keyType.cast(new JCEAESKey(this, encodedKeyData));
                } else if (HMACSHA1Key.class.isAssignableFrom(keyType) && (encodedKey.getFormat() == RAW)) {
                    return keyType.cast(new JCEHMACSHA1Key(this, encodedKeyData));
                } else if (HMACSHA256Key.class.isAssignableFrom(keyType) && (encodedKey.getFormat() == RAW)) {
                    return keyType.cast(new JCEHMACSHA256Key(this, encodedKeyData));
                } else if (HMACSHA512Key.class.isAssignableFrom(keyType) && (encodedKey.getFormat() == RAW)) {
                    return keyType.cast(new JCEHMACSHA512Key(this, encodedKeyData));
                } else if (RSAPrivateKey.class.isAssignableFrom(keyType) && (encodedKey.getFormat() == PKCS8)) {
                    return keyType.cast(new JCERSAPrivateKey(this, KeyFactory.getInstance("RSA")
                            .generatePrivate(new PKCS8EncodedKeySpec(encodedKeyData))));
                } else if (RSAPublicKey.class.isAssignableFrom(keyType) && (encodedKey.getFormat() == X509)) {
                    return keyType.cast(new JCERSAPublicKey(this, KeyFactory.getInstance("RSA")
                            .generatePublic(new X509EncodedKeySpec(encodedKeyData))));
                } else if (DHPrivateKey.class.isAssignableFrom(keyType) && (encodedKey.getFormat() == PKCS8)) {
                    return keyType.cast(new JCEDHPrivateKey(this, KeyFactory.getInstance("DH")
                            .generatePrivate(new PKCS8EncodedKeySpec(encodedKeyData))));
                } else if (DHPublicKey.class.isAssignableFrom(keyType) && (encodedKey.getFormat() == X509)) {
                    return keyType.cast(new JCEDHPublicKey(this, KeyFactory.getInstance("DH")
                            .generatePublic(new X509EncodedKeySpec(encodedKeyData))));
                } else {
                    throw new InvalidKeyException("Unsupported key type " + keyType.getName() + " and format " + encodedKey.getFormat().name());
                }
            } catch (NoSuchAlgorithmException e) {
                throw new UnexpectedException(e);
            } catch (InvalidKeySpecException e) {
                throw new InvalidKeyException(e);
            }
        }
    }

    @Override
    public <K extends com.kloudtek.kryptotek.Key> K readKey(@NotNull Class<K> keyType, @NotNull byte[] encodedKey) throws InvalidKeyException {
        if (AESKey.class.isAssignableFrom(keyType) || HMACKey.class.isAssignableFrom(keyType)) {
            return readKey(keyType, new EncodedKey(encodedKey, RAW));
        } else if (RSAPrivateKey.class.isAssignableFrom(keyType)) {
            return readKey(keyType, EncodedKey.rsaPrivatePkcs8(encodedKey));
        } else if (RSAPublicKey.class.isAssignableFrom(keyType)) {
            return readKey(keyType, EncodedKey.rsaPublicX509(encodedKey));
        } else if (RSAKeyPair.class.isAssignableFrom(keyType)) {
            return readKey(keyType, new EncodedKey(encodedKey, EncodedKey.Format.SERIALIZED));
        } else if (DHPrivateKey.class.isAssignableFrom(keyType)) {
            return readKey(keyType, EncodedKey.rsaPrivatePkcs8(encodedKey));
        } else if (DHPublicKey.class.isAssignableFrom(keyType)) {
            return readKey(keyType, EncodedKey.rsaPublicX509(encodedKey));
        } else if (DHKeyPair.class.isAssignableFrom(keyType)) {
            return readKey(keyType, new EncodedKey(encodedKey, EncodedKey.Format.SERIALIZED));
        } else {
            throw new InvalidKeyException("Unsupported key type " + keyType.getName());
        }
    }

    @Override
    public byte[] encrypt(@NotNull EncryptionKey key, @NotNull byte[] data, boolean compatibilityMode) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return crypt(key, data, true, getJceDefaultAlg(key, compatibilityMode));
    }

    @Override
    public byte[] encrypt(@NotNull EncryptionKey key, @NotNull byte[] data, String cipherAlgorithm) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return crypt(key, data, true, cipherAlgorithm);
    }

    @Override
    public byte[] encrypt(@NotNull EncryptionKey key, @NotNull SymmetricAlgorithm symmetricAlgorithm, int symmetricKeySize, @NotNull byte[] data, boolean compatibilityMode) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return encrypt(key, symmetricAlgorithm, symmetricAlgorithm.getDefaultCipherAlg(compatibilityMode), symmetricKeySize, data, getJceDefaultAlg(key, compatibilityMode));
    }

    @Override
    public byte[] encrypt(@NotNull EncryptionKey key, @NotNull SymmetricAlgorithm symmetricAlgorithm, @NotNull String symmetricAlgorithmCipher, int symmetricKeySize, @NotNull byte[] data, @NotNull String cipherAlgorithm) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        checkJceKey(key);
        ByteArrayDataOutputStream buf = new ByteArrayDataOutputStream();
        try {
            try {
                byte[] encryptedData = crypt(key, data, true, cipherAlgorithm);
                buf.writeShort(0);
                buf.write(encryptedData);
            } catch (IllegalBlockSizeException e) {
                // TODO Use a better to check for payload larger than algorithm can handle
                if (symmetricAlgorithm != SymmetricAlgorithm.AES) {
                    throw new IllegalArgumentException("Unsupported asymmetric cryptography");
                }
                AESKey sKey = generateKey(AESKey.class, symmetricKeySize);
                byte[] encryptedSecretKey = encrypt(key, sKey.getEncoded().getEncodedKey(), cipherAlgorithm);
                buf.writeShort(encryptedSecretKey.length);
                buf.write(encryptedSecretKey);
                buf.write(encrypt(sKey, data, symmetricAlgorithmCipher));
                sKey.destroy();
            }
        } catch (IOException e) {
            throw new UnexpectedException(e);
        }
        return buf.toByteArray();
    }

    @Override
    public byte[] decrypt(@NotNull DecryptionKey key, @NotNull byte[] data, boolean compatibilityMode) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return decrypt(key, data, getJceDefaultAlg(key, compatibilityMode));
    }

    @Override
    public byte[] decrypt(@NotNull DecryptionKey key, @NotNull byte[] data, String cipherAlgorithm) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return crypt(key, data, false, cipherAlgorithm);
    }

    @Override
    public byte[] decrypt(@NotNull DecryptionKey key, @NotNull SymmetricAlgorithm symmetricAlgorithm, int symmetricKeySize, @NotNull byte[] data, boolean compatibilityMode) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return decrypt(key, symmetricAlgorithm, null, symmetricKeySize, data, getJceDefaultAlg(key, compatibilityMode));
    }

    @Override
    public byte[] decrypt(@NotNull DecryptionKey key, @NotNull SymmetricAlgorithm symmetricAlgorithm, @Nullable String symmetricAlgorithmCipher, int symmetricKeySize, @NotNull byte[] data, @NotNull String cipherAlgorithm) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        checkJceKey(key);
        if (data.length < 3) {
            throw new IllegalArgumentException("Encrypted data is invalid");
        }
        if (symmetricAlgorithmCipher == null) {
            symmetricAlgorithmCipher = symmetricAlgorithm.getDefaultCipherAlg(defaultCompatibilityMode);
        }
        try {
            ByteArrayDataInputStream is = new ByteArrayDataInputStream(data);
            short skeyLen = is.readShort();
            if (skeyLen <= 0) {
                byte[] encryptedData = is.readFully(data.length - 2);
                return crypt(key, encryptedData, false, cipherAlgorithm);
            } else {
                byte[] encodedSKeyData = is.readFully(skeyLen);
                byte[] encodedSKey = crypt(key, encodedSKeyData, false, cipherAlgorithm);
                byte[] encryptedData = is.readFully(data.length - 2 - skeyLen);
                com.kloudtek.kryptotek.Key sKey = readKey(symmetricAlgorithm.getKeyClass(), encodedSKey);
                return crypt(sKey, encryptedData, false, symmetricAlgorithmCipher);
            }
        } catch (IOException e) {
            throw new IllegalArgumentException("Encrypted data is invalid");
        }
    }

    private byte[] crypt(com.kloudtek.kryptotek.Key key, byte[] data, boolean encryptMode, String cipherAlgorithm) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        try {
            checkJceKey(key);
            if (key instanceof JCESecretKey) {
                return crypt(cipherAlgorithm, ((JCESecretKey) key).getSecretKey(), data, encryptMode);
            } else if (key instanceof JCEKeyPair) {
                java.security.KeyPair keyPair = ((JCEKeyPair) key).getJCEKeyPair();
                return crypt(cipherAlgorithm, encryptMode ? keyPair.getPublic() : keyPair.getPrivate(), data, encryptMode);
            } else if (key instanceof JCEPublicKey) {
                return crypt(cipherAlgorithm, ((JCEPublicKey) key).getJCEPublicKey(), data, encryptMode);
            } else if (key instanceof JCEPrivateKey) {
                return crypt(cipherAlgorithm, ((JCEPrivateKey) key).getJCEPrivateKey(), data, encryptMode);
            } else {
                throw new IllegalArgumentException("Unable to perform de/encryption operation using key of type " + key.getClass().getName());
            }
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedException(e);
        } catch (NoSuchPaddingException e) {
            throw new UnexpectedException(e);
        }
    }

    private byte[] crypt(@NotNull String cipherAlgorithm, @NotNull java.security.Key key, @NotNull byte[] data,
                         boolean encrypt) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        try {
            Cipher cipher = Cipher.getInstance(cipherAlgorithm);
            if (cipherAlgorithm.startsWith("AES/CBC")) {
                if (encrypt) {
                    byte[] iv = new byte[16];
                    CryptoUtils.rng().nextBytes(iv);
                    cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
                    final byte[] encryptedData = cipher.doFinal(data);
                    return ArrayUtils.concat(iv, encryptedData);
                } else {
                    byte[] iv = Arrays.copyOfRange(data, 0, 16);
                    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
                    return cipher.doFinal(Arrays.copyOfRange(data, 16, data.length));
                }
            } else {
                cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, key);
                return cipher.doFinal(data);
            }
        } catch (InvalidAlgorithmParameterException e) {
            throw new UnexpectedException(e);
        }
    }

    @Override
    public byte[] sign(@NotNull SigningKey key, @Nullable DigestAlgorithm digestAlgorithm, @NotNull byte[] data) throws InvalidKeyException {
        try {
            if (digestAlgorithm == null) {
                digestAlgorithm = DigestAlgorithm.SHA256;
            }
            if (key instanceof JCERSAKeyPair) {
                RSAPrivateKey rsaPrivateKey = getRSAPrivateKey(key);
                if (rsaPrivateKey != null) {
                    return sign(rsaPrivateKey, digestAlgorithm, data);
                }
            } else if (key instanceof JCERSAPrivateKey) {
                Signature signature = Signature.getInstance(digestAlgorithm.name() + "withRSA");
                signature.initSign(((JCERSAPrivateKey) key).getJCEPrivateKey());
                signature.update(data);
                return signature.sign();
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
                    sig.initVerify(publicKey.getJCEPublicKey());
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

    @NotNull
    @Override
    public AESKey generatePBEAESKey(char[] password, int iterations, byte[] salt, int keyLen) {
        try {
            KeySpec keySpec = new PBEKeySpec(password, salt, iterations, keyLen);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(PBKDF_2_WITH_HMAC_SHA_1);
            return new JCEAESKey(this, new SecretKeySpec(keyFactory.generateSecret(keySpec).getEncoded(), "AES"));
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedException(e);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException("Invalid key parameters", e);
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

    private JCERSAPublicKey getRSAPublicKey(com.kloudtek.kryptotek.Key key) {
        if (key instanceof JCERSAPublicKey) {
            return (JCERSAPublicKey) key;
        } else if (key instanceof JCEKeyPair) {
            return new JCERSAPublicKey(this, ((JCEKeyPair) key).getJCEKeyPair().getPublic());
        } else {
            return null;
        }
    }

    private JCERSAPrivateKey getRSAPrivateKey(com.kloudtek.kryptotek.Key key) {
        if (key instanceof JCERSAPrivateKey) {
            return (JCERSAPrivateKey) key;
        } else if (key instanceof JCEKeyPair) {
            return new JCERSAPrivateKey(this, ((JCEKeyPair) key).getJCEKeyPair().getPrivate());
        } else {
            return null;
        }
    }

    private void checkJceKey(com.kloudtek.kryptotek.Key key) {
        if (!(key instanceof JCEKey)) {
            throw new IllegalArgumentException("Key must be a JCE key");
        }
    }

    private String getJceDefaultAlg(com.kloudtek.kryptotek.Key key, boolean compatibilityMode) {
        String jceCryptAlgorithm = ((JCEKey) key).getJceCryptAlgorithm(compatibilityMode);
        if (jceCryptAlgorithm == null) {
            throw new IllegalArgumentException("Unable to perform de/encryption operation using key of type " + key.getClass().getName());
        }
        return jceCryptAlgorithm;
    }

    private HMACKey createHmacKey(DigestAlgorithm digestAlgorithm, SecretKey secretKey) {
        switch (digestAlgorithm) {
            case SHA1:
                return new JCEHMACSHA1Key(this, secretKey);
            case SHA256:
                return new JCEHMACSHA256Key(this, secretKey);
            case SHA512:
                return new JCEHMACSHA512Key(this, secretKey);
            default:
                throw new IllegalArgumentException("Cannot create an hmac key of type " + digestAlgorithm.name());
        }
    }

    private byte[] agreeDHKey(DHPrivateKey dhPrivateKey, DHPublicKey dhPublicKey) throws InvalidKeyException {
        try {
            KeyAgreement ka = KeyAgreement.getInstance("DH");
            ka.init(((JCEDHPrivateKey) dhPrivateKey).getJCEPrivateKey());
            ka.doPhase(((JCEDHPublicKey) dhPublicKey).getJCEPublicKey(), true);
            return ka.generateSecret();
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedException(e);
        }
    }
}
