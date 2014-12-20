/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek;

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

    public void testRSAEncryption(CryptoEngine cryptoEngine) throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        Key keyPair = cryptoEngine.generateKey(Key.Type.RSA_KEYPAIR, 1024);
        byte[] encrypted = cryptoEngine.encrypt(keyPair, DATA, true);
        byte[] decrypted = cryptoEngine.decrypt(keyPair, encrypted, true);
        Assert.assertEquals(decrypted, DATA);
    }

    public void testShortRSAAESEncryption(CryptoEngine cryptoEngine) throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        Key keyPair = cryptoEngine.generateKey(Key.Type.RSA_KEYPAIR, 1024);
        byte[] encrypted = cryptoEngine.encrypt(keyPair, SymmetricAlgorithm.AES, 128, DATA, true);
        Assert.assertEquals(encrypted[0], 0);
        byte[] decrypted = cryptoEngine.decrypt(keyPair, SymmetricAlgorithm.AES, 128, encrypted, true);
        Assert.assertEquals(decrypted, DATA);
    }

    public void testLongRSAAESEncryption(CryptoEngine cryptoEngine) throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        Key keyPair = cryptoEngine.generateKey(Key.Type.RSA_KEYPAIR, 1024);
        byte[] encrypted = cryptoEngine.encrypt(keyPair, SymmetricAlgorithm.AES, 128, DATA_LONG, true);
        byte[] decrypted = cryptoEngine.decrypt(keyPair, SymmetricAlgorithm.AES, 128, encrypted, true);
        Assert.assertEquals(decrypted, DATA_LONG);
    }

    public void testAesEncryption(CryptoEngine cryptoEngine) throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        Key key = cryptoEngine.generateKey(Key.Type.AES, 128);
        byte[] encrypted = cryptoEngine.encrypt(key, DATA, true);
        byte[] decrypted = cryptoEngine.decrypt(key, encrypted, true);
        Assert.assertEquals(decrypted, DATA);
    }

    public void testRSASigning(CryptoEngine cryptoEngine) throws SignatureException, InvalidKeyException {
        Key keyPair = cryptoEngine.generateKey(Key.Type.RSA_KEYPAIR, 1024);
        byte[] signature = cryptoEngine.sign(keyPair, DigestAlgorithm.SHA256, DATA);
        cryptoEngine.verifySignature(keyPair, DigestAlgorithm.SHA256, DATA, signature);
    }

}
