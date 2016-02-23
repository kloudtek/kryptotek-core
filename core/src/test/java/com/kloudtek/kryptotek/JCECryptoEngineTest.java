/*
 * Copyright (c) 2016 Kloudtek Ltd
 */

package com.kloudtek.kryptotek;

import com.kloudtek.kryptotek.jce.JCECryptoEngine;
import com.kloudtek.kryptotek.test.AbstractCryptoEngineTest;
import org.testng.Assert;
import org.testng.annotations.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.security.InvalidKeyException;
import java.security.SignatureException;


public class JCECryptoEngineTest extends AbstractCryptoEngineTest {
    private JCECryptoEngine jceCryptoEngine = new JCECryptoEngine();

    @Test
    public void testRSAEncryption() throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        testRSAEncryption(jceCryptoEngine);
    }

    @Test
    public void testHmacSigning() throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException, SignatureException {
        testHmacSigning(jceCryptoEngine);
    }

    @Test
    public void testHmacSigningInvalidSig() throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException, SignatureException {
        testHmacSigningInvalidSig(jceCryptoEngine);
    }

    @Test
    public void testShortRSAAESEncryption() throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        testShortRSAAESEncryption(jceCryptoEngine);
    }

    @Test
    public void testLongRSAAESEncryption() throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        testLongRSAAESEncryption(jceCryptoEngine);
    }

    @Test
    public void testAesEncryption() throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        testAesEncryption(jceCryptoEngine);
    }

    @Test
    public void testRSASigning() throws SignatureException, InvalidKeyException {
        testRSASigning(jceCryptoEngine);
    }

    @Test
    public void testSerializeCert() throws InvalidKeyEncodingException, InvalidKeyException {
        super.testSerializeCert(jceCryptoEngine);
    }

    @Test
    public void testSerializeAesKey() throws InvalidKeyEncodingException, InvalidKeyException {
        super.testSerializeAesKey(jceCryptoEngine);
    }

    @Test
    public void testSerializeHMACSHA1Key() throws InvalidKeyEncodingException, InvalidKeyException {
        super.testSerializeHMACSHA1Key(jceCryptoEngine);
    }

    @Test
    public void testSerializeHMACSHA256Key() throws InvalidKeyEncodingException, InvalidKeyException {
        super.testSerializeHMACSHA256Key(jceCryptoEngine);
    }

    @Test
    public void testSerializeHMACSHA512Key() throws InvalidKeyEncodingException, InvalidKeyException {
        super.testSerializeHMACSHA512Key(jceCryptoEngine);
    }

    @Test
    public void testSerializeRSAPrivateKey() throws InvalidKeyEncodingException, InvalidKeyException {
        super.testSerializeRSAPrivateKey(jceCryptoEngine);
    }

    @Test
    public void testSerializeRSAPublicKey() throws InvalidKeyEncodingException, InvalidKeyException {
        super.testSerializeRSAPublicKey(jceCryptoEngine);
    }

    @Test
    public void testSerializeRSAKeyPair() throws InvalidKeyEncodingException, InvalidKeyException {
        super.testSerializeRSAKeyPair(jceCryptoEngine);
    }

    @Test
    public void testHmacDHExchange() throws InvalidKeyException, SignatureException {
        super.testHmacDHExchange(jceCryptoEngine);
    }

    @Test
    public void testAESDHExchange() throws InvalidKeyException, SignatureException, BadPaddingException, IllegalBlockSizeException {
        super.testAESDHExchange(jceCryptoEngine);
    }

    @Test
    public void testGeneratePBEAESKey() throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        super.testGeneratePBEAESKey(jceCryptoEngine);
    }

    @Test
    public void testGeneratePBEHMACKey() throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException, SignatureException {
        super.testGeneratePBEHMACKey(jceCryptoEngine);
    }

    @Override
    protected void assertEquals(byte[] actual, byte[] expected) {
        Assert.assertEquals(actual, expected);
    }

    @Override
    protected void assertEquals(int actual, int expected) {
        Assert.assertEquals(actual, expected);
    }

    @Override
    protected void assertEquals(Object actual, Object expected) {
        Assert.assertEquals(actual, expected);
    }

    @Override
    protected void fail(String reason) {
        Assert.fail(reason);
    }
}
