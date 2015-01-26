/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.jce;

import com.kloudtek.kryptotek.DigestAlgorithm;
import com.kloudtek.kryptotek.EncodedKey;
import com.kloudtek.kryptotek.InvalidKeyEncodingException;
import com.kloudtek.kryptotek.key.HMACKey;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;

/**
 * Created by yannick on 18/12/2014.
 */
public abstract class JCEHMACKey extends JCESecretKey implements HMACKey {
    private final DigestAlgorithm digestAlgorithm;

    public JCEHMACKey(DigestAlgorithm digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    public JCEHMACKey(JCECryptoEngine cryptoEngine, DigestAlgorithm digestAlgorithm, SecretKey secretKey) {
        super(cryptoEngine, secretKey);
        this.digestAlgorithm = digestAlgorithm;
    }

    public JCEHMACKey(JCECryptoEngine cryptoEngine, DigestAlgorithm digestAlgorithm, EncodedKey encodedKey) throws InvalidKeyEncodingException, InvalidKeyException {
        super(cryptoEngine);
        this.digestAlgorithm = digestAlgorithm;
        readEncodedKey(encodedKey);
    }

    public JCEHMACKey(JCECryptoEngine cryptoEngine, DigestAlgorithm digestAlgorithm, byte[] rawEncodedSecretKey) {
        super(cryptoEngine);
        this.digestAlgorithm = digestAlgorithm;
        setDefaultEncoded(rawEncodedSecretKey);
    }

    @Override
    public EncodedKey.Format getDefaultEncoding() {
        return EncodedKey.Format.RAW;
    }

    @Override
    public void setDefaultEncoded(byte[] encodedKey) {
        key = new SecretKeySpec(encodedKey,"Hmac"+digestAlgorithm.name());
    }

    @Override
    public DigestAlgorithm getDigestAlgorithm() {
        return digestAlgorithm;
    }
}
