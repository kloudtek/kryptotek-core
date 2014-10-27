/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.rest.client;

import com.kloudtek.kryptotek.CryptoUtils;
import com.kloudtek.kryptotek.DigestAlgorithm;
import com.kloudtek.util.StringUtils;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;

/**
 * Created by yannick on 23/10/2014.
 */
public class HmacHCInterceptorI extends HCInterceptor {
    private SecretKey secretKey;
    private DigestAlgorithm digestAlgorithm;

    public HmacHCInterceptorI(DigestAlgorithm digestAlgorithm, String identity, SecretKey secretKey) {
        super(identity);
        this.digestAlgorithm = digestAlgorithm;
        this.secretKey = secretKey;
    }

    public HmacHCInterceptorI(DigestAlgorithm digestAlgorithm, String identity, byte[] secretKey) {
        super(identity);
        this.digestAlgorithm = digestAlgorithm;
        this.secretKey = new SecretKeySpec(secretKey,"RAW");
    }

    @Override
    protected String sign(byte[] data) throws InvalidKeyException {
        return StringUtils.base64Encode(CryptoUtils.hmac(digestAlgorithm,secretKey, data));
    }
}
