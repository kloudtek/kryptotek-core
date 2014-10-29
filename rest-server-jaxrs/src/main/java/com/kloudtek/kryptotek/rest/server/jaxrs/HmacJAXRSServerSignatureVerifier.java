/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.rest.server.jaxrs;

import com.kloudtek.kryptotek.CryptoUtils;
import com.kloudtek.kryptotek.DigestAlgorithm;
import com.kloudtek.util.StringUtils;

import javax.crypto.SecretKey;
import javax.ws.rs.WebApplicationException;
import java.security.InvalidKeyException;
import java.util.logging.Level;
import java.util.logging.Logger;

import static javax.ws.rs.core.Response.Status.INTERNAL_SERVER_ERROR;

/**
 * Created by yannick on 28/10/2014.
 */
public abstract class HmacJAXRSServerSignatureVerifier extends JAXRSServerSignatureVerifier {
    private static final Logger logger = Logger.getLogger(HmacJAXRSServerSignatureVerifier.class.getName());
    private DigestAlgorithm digestAlgorithm;

    protected HmacJAXRSServerSignatureVerifier(DigestAlgorithm digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    @Override
    protected boolean verifySignature(String identity, byte[] dataToSign, String signature) {
        SecretKey key = findKey(identity);
        if (key == null) {
            return false;
        }
        try {
            return signature.equals(StringUtils.base64Encode(CryptoUtils.hmac(digestAlgorithm, key, dataToSign)));
        } catch (InvalidKeyException e) {
            logger.log(Level.SEVERE, "Invalid key found while verifying signature: " + e.getMessage(), e);
            throw new WebApplicationException(INTERNAL_SERVER_ERROR);
        }
    }

    protected abstract SecretKey findKey(String identity);
}
