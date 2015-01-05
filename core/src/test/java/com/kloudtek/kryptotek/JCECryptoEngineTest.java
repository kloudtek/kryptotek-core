/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek;

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
}
