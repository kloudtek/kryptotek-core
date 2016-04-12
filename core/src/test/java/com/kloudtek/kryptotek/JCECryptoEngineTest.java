/*
 * Copyright (c) 2016 Kloudtek Ltd
 */

package com.kloudtek.kryptotek;

import com.kloudtek.kryptotek.jce.JCECryptoEngine;
import com.kloudtek.kryptotek.test.AbstractCryptoEngineTest;
import org.testng.Assert;
import org.testng.annotations.Test;


public class JCECryptoEngineTest extends AbstractCryptoEngineTest {
    private JCECryptoEngine jceCryptoEngine = new JCECryptoEngine();

    @Test
    public void testRSAEncryption() throws Exception {
        testRSAEncryption(jceCryptoEngine);
    }

    @Test
    public void testHmacSigning() throws Exception {
        testHmacSigning(jceCryptoEngine);
    }

    @Test
    public void testHmacSigningInvalidSig() throws Exception {
        testHmacSigningInvalidSig(jceCryptoEngine);
    }

    @Test
    public void testShortRSAAESEncryption() throws Exception {
        testShortRSAAESEncryption(jceCryptoEngine);
    }

    @Test
    public void testLongRSAAESEncryption() throws Exception {
        testLongRSAAESEncryption(jceCryptoEngine);
    }

    @Test
    public void testAesEncryption() throws Exception {
        testAesEncryption(jceCryptoEngine);
    }

    @Test
    public void testRSASigning() throws Exception {
        testRSASigning(jceCryptoEngine);
    }

    @Test
    public void testSerializeCert() throws Exception {
        super.testSerializeCert(jceCryptoEngine);
    }

    @Test
    public void testSerializeAesKey() throws Exception {
        super.testSerializeAesKey(jceCryptoEngine);
    }

    @Test
    public void testSerializeHMACSHA1Key() throws Exception {
        super.testSerializeHMACSHA1Key(jceCryptoEngine);
    }

    @Test
    public void testSerializeHMACSHA256Key() throws Exception {
        super.testSerializeHMACSHA256Key(jceCryptoEngine);
    }

    @Test
    public void testSerializeHMACSHA512Key() throws Exception {
        super.testSerializeHMACSHA512Key(jceCryptoEngine);
    }

    @Test
    public void testSerializeRSAPrivateKey() throws Exception {
        super.testSerializeRSAPrivateKey(jceCryptoEngine);
    }

    @Test
    public void testSerializeRSAPublicKey() throws Exception {
        super.testSerializeRSAPublicKey(jceCryptoEngine);
    }

    @Test
    public void testSerializeRSAKeyPair() throws Exception {
        super.testSerializeRSAKeyPair(jceCryptoEngine);
    }

    @Test
    public void testHmacDHExchange() throws Exception {
        super.testHmacDHExchange(jceCryptoEngine);
    }

    @Test
    public void testAESDHExchange() throws Exception {
        super.testAESDHExchange(jceCryptoEngine);
    }

    @Test
    public void testGeneratePBEAESKey() throws Exception {
        super.testGeneratePBEAESKey(jceCryptoEngine);
    }

    @Test
    public void testGeneratePBEHMACKey() throws Exception {
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
