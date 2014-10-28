/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.rest.client.httpcomponents;

import com.kloudtek.kryptotek.CryptoUtils;
import com.kloudtek.kryptotek.DigestAlgorithm;
import com.kloudtek.util.StringUtils;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;

/**
 * Created by yannick on 23/10/2014.
 */
public class RSAHCInterceptor extends HCInterceptor {
    private PrivateKey clientKey;
    private PublicKey serverKey;
    private DigestAlgorithm digestAlgorithm;

    public RSAHCInterceptor(DigestAlgorithm digestAlgorithm, String identity, PrivateKey clientKey, PublicKey serverKey,
                            TimeSync timeSync, Long responseSizeLimit) {
        super(identity, timeSync, responseSizeLimit);
        this.digestAlgorithm = digestAlgorithm;
        this.clientKey = clientKey;
        this.serverKey = serverKey;
    }

    @Override
    protected String sign(byte[] data) throws InvalidKeyException, SignatureException {
        return StringUtils.base64Encode(CryptoUtils.rsaSign(digestAlgorithm, clientKey, data));
    }

    @Override
    protected void verifySignature(String signature, byte[] signedData) throws InvalidKeyException, SignatureException {
        CryptoUtils.rsaVerifySignature(digestAlgorithm, serverKey, signedData, StringUtils.base64Decode(signature));
    }
}
