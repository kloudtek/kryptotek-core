/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.key.jce;

import com.kloudtek.kryptotek.DigestAlgorithm;
import com.kloudtek.kryptotek.EncodedKey;
import com.kloudtek.kryptotek.InvalidKeyEncodingException;
import com.kloudtek.kryptotek.JCECryptoEngine;
import com.kloudtek.kryptotek.key.HMACKey;
import com.kloudtek.kryptotek.key.HMACSHA256Key;
import com.kloudtek.kryptotek.key.HMACSHA512Key;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.security.InvalidKeyException;

import static com.kloudtek.kryptotek.CryptoAlgorithm.HMAC;

/**
 * Created by yannick on 18/12/2014.
 */
public class JCEHMACSHA512Key extends JCEHMACKey implements HMACSHA512Key {
    public JCEHMACSHA512Key(JCECryptoEngine cryptoEngine, SecretKey secretKey) {
        super(cryptoEngine, DigestAlgorithm.SHA512,secretKey);
    }

    public JCEHMACSHA512Key(JCECryptoEngine cryptoEngine, byte[] encodedRawKey) {
        super(cryptoEngine, DigestAlgorithm.SHA512,encodedRawKey);
    }

    public JCEHMACSHA512Key(JCECryptoEngine cryptoEngine, EncodedKey encodedKey) throws InvalidKeyEncodingException, InvalidKeyException {
        super(cryptoEngine, DigestAlgorithm.SHA512, encodedKey);
    }
}
