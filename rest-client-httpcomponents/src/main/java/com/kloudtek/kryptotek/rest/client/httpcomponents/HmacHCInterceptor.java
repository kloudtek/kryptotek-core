/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.rest.client.httpcomponents;

import com.kloudtek.kryptotek.CryptoUtils;
import com.kloudtek.kryptotek.DigestAlgorithm;
import com.kloudtek.util.StringUtils;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;

/**
 * Created by yannick on 23/10/2014.
 */
public class HmacHCInterceptor extends HCInterceptor {
    private SecretKey secretKey;
    private DigestAlgorithm digestAlgorithm;

    public HmacHCInterceptor(DigestAlgorithm digestAlgorithm, String identity, SecretKey secretKey, TimeSync timeSync) {
        super(identity, timeSync);
        this.digestAlgorithm = digestAlgorithm;
        this.secretKey = secretKey;
    }

    public HmacHCInterceptor(DigestAlgorithm digestAlgorithm, String identity, byte[] secretKey, TimeSync timeSync) {
        this(digestAlgorithm, identity, new SecretKeySpec(secretKey, "RAW"), timeSync);
    }

    @Override
    protected String sign(byte[] data) throws InvalidKeyException {
        return StringUtils.base64Encode(CryptoUtils.hmac(digestAlgorithm, secretKey, data));
    }
}
