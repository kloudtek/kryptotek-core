/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek;

import com.kloudtek.kryptotek.key.AESKey;
import com.kloudtek.kryptotek.key.HMACKey;
import com.kloudtek.kryptotek.key.RSAKeyPair;
import com.kloudtek.kryptotek.key.SimpleCertificate;
import org.testng.Assert;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.Random;


public class AbstractCryptoEngineTest extends Assert {
    public static final byte[] DATA = "SOMEDATA".getBytes();
    public static final byte[] DATA_LONG;

    static {
        DATA_LONG = new byte[10000];
        new Random().nextBytes(DATA_LONG);
    }

    public static final String SUBJECT = "some-subject";

    public void testAesEncryption(CryptoEngine cryptoEngine) throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        AESKey key = cryptoEngine.generateAESKey(128);
        byte[] encrypted = cryptoEngine.encrypt(key, DATA, true);
        byte[] decrypted = cryptoEngine.decrypt(key, encrypted, true);
        Assert.assertEquals(decrypted, DATA);
    }

    public void testHmacSigning(CryptoEngine cryptoEngine) throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException, SignatureException {
        HMACKey key = cryptoEngine.generateHMACKey(DigestAlgorithm.SHA256);
        byte[] signature = cryptoEngine.sign(key, DATA);
        cryptoEngine.verifySignature(key, DATA, signature);
    }

    public void testHmacSigningInvalidSig(CryptoEngine cryptoEngine) throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException, SignatureException {
        HMACKey key = cryptoEngine.generateHMACKey(DigestAlgorithm.SHA256);
        byte[] signature = cryptoEngine.sign(key, DATA);
        try {
            cryptoEngine.verifySignature(key, DATA, "asfdfsdaafds".getBytes());
            fail("didn't fail with invalid hmac signature");
        } catch (SignatureException e) {
            // ok
        }
    }

    public void testRSAEncryption(CryptoEngine cryptoEngine) throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        RSAKeyPair keyPair = cryptoEngine.generateRSAKeyPair(1024);
        byte[] encrypted = cryptoEngine.encrypt(keyPair, DATA, true);
        byte[] decrypted = cryptoEngine.decrypt(keyPair, encrypted, true);
        Assert.assertEquals(decrypted, DATA);
    }

    public void testShortRSAAESEncryption(CryptoEngine cryptoEngine) throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        RSAKeyPair keyPair = cryptoEngine.generateRSAKeyPair(1024);
        byte[] encrypted = cryptoEngine.encrypt(keyPair, SymmetricAlgorithm.AES, 128, DATA, true);
        Assert.assertEquals(encrypted[0], 0);
        byte[] decrypted = cryptoEngine.decrypt(keyPair, SymmetricAlgorithm.AES, 128, encrypted, true);
        Assert.assertEquals(decrypted, DATA);
    }

    public void testLongRSAAESEncryption(CryptoEngine cryptoEngine) throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        RSAKeyPair keyPair = cryptoEngine.generateRSAKeyPair(1024);
        byte[] encrypted = cryptoEngine.encrypt(keyPair, SymmetricAlgorithm.AES, 128, DATA_LONG, true);
        byte[] decrypted = cryptoEngine.decrypt(keyPair, SymmetricAlgorithm.AES, 128, encrypted, true);
        Assert.assertEquals(decrypted, DATA_LONG);
    }

    public void testRSASigning(CryptoEngine cryptoEngine) throws SignatureException, InvalidKeyException {
        RSAKeyPair keyPair = cryptoEngine.generateRSAKeyPair(1024);
        byte[] signature = cryptoEngine.sign(keyPair, DigestAlgorithm.SHA256, DATA);
        cryptoEngine.verifySignature(keyPair, DigestAlgorithm.SHA256, DATA, signature);
    }

    public void testSerializeSimpleCert(CryptoEngine cryptoEngine) throws InvalidKeyEncodingException, InvalidKeyException {
        RSAKeyPair keyPair = cryptoEngine.generateRSAKeyPair(2048);
        SimpleCertificate simpleCertificate = cryptoEngine.generateSimpleCertificate(SUBJECT, keyPair.getPublicKey());
        verifySerializedKey(cryptoEngine, simpleCertificate);
    }

    public void testSerializeAesKey(CryptoEngine cryptoEngine) throws InvalidKeyEncodingException, InvalidKeyException {
        verifySerializedKey(cryptoEngine, cryptoEngine.generateAESKey(256));
    }

    public void testSerializeHMACSHA1Key(CryptoEngine cryptoEngine) throws InvalidKeyEncodingException, InvalidKeyException {
        verifySerializedKey(cryptoEngine, cryptoEngine.generateHMACKey(DigestAlgorithm.SHA1));
    }

    public void testSerializeHMACSHA256Key(CryptoEngine cryptoEngine) throws InvalidKeyEncodingException, InvalidKeyException {
        verifySerializedKey(cryptoEngine, cryptoEngine.generateHMACKey(DigestAlgorithm.SHA256));
    }

    public void testSerializeHMACSHA512Key(CryptoEngine cryptoEngine) throws InvalidKeyEncodingException, InvalidKeyException {
        verifySerializedKey(cryptoEngine, cryptoEngine.generateHMACKey(DigestAlgorithm.SHA256));
    }

    public void testSerializeRSAPrivateKey(CryptoEngine cryptoEngine) throws InvalidKeyEncodingException, InvalidKeyException {
        verifySerializedKey(cryptoEngine, cryptoEngine.generateRSAKeyPair(2048).getPrivateKey());
    }

    public void testSerializeRSAPublicKey(CryptoEngine cryptoEngine) throws InvalidKeyEncodingException, InvalidKeyException {
        verifySerializedKey(cryptoEngine, cryptoEngine.generateRSAKeyPair(2048).getPublicKey());
    }

    public void testSerializeRSAKeyPair(CryptoEngine cryptoEngine) throws InvalidKeyEncodingException, InvalidKeyException {
        verifySerializedKey(cryptoEngine, cryptoEngine.generateRSAKeyPair(2048));
    }

    private void verifySerializedKey(CryptoEngine cryptoEngine, Key key) throws InvalidKeyEncodingException, InvalidKeyException {
        EncodedKey encodedKey = key.getEncoded(EncodedKey.Format.SERIALIZED);
        Key deserializedKey = cryptoEngine.readKey(Key.class, encodedKey);
        assertEquals(deserializedKey, key);
    }
}
