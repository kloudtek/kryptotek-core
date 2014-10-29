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
import java.security.SignatureException;

/**
 * Created by yannick on 23/10/2014.
 */
public class HmacHCInterceptor extends HCInterceptor {
    private SecretKey secretKey;
    private DigestAlgorithm digestAlgorithm;

    public HmacHCInterceptor(DigestAlgorithm digestAlgorithm, String identity, SecretKey secretKey, TimeSync timeSync, Long responseSizeLimit) {
        super(identity, timeSync, responseSizeLimit);
        this.digestAlgorithm = digestAlgorithm;
        this.secretKey = secretKey;
    }

    public HmacHCInterceptor(DigestAlgorithm digestAlgorithm, String identity, byte[] secretKey, TimeSync timeSync, Long responseSizeLimit) {
        this(digestAlgorithm, identity, new SecretKeySpec(secretKey, "RAW"), timeSync, responseSizeLimit );
    }

    @Override
    protected String sign(byte[] data) throws InvalidKeyException {
        return StringUtils.base64Encode(CryptoUtils.hmac(digestAlgorithm, secretKey, data));
    }

    @Override
    protected void verifySignature(String signature, byte[] signedData) throws InvalidKeyException, SignatureException {
        if (!sign(signedData).trim().equals(signature.trim())) {
            throw new SignatureException();
        }
    }

    public HmacHCInterceptor(String identity, TimeSync timeSync, Long responseSizeLimit, SecretKey secretKey, DigestAlgorithm digestAlgorithm) {
        super(identity, timeSync, responseSizeLimit);
        this.secretKey = secretKey;
        this.digestAlgorithm = digestAlgorithm;
    }
}
