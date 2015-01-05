/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.rest.server.jaxrs;

import com.kloudtek.kryptotek.CryptoUtils;
import com.kloudtek.kryptotek.DigestAlgorithm;
import com.kloudtek.kryptotek.Key;
import com.kloudtek.kryptotek.key.SignatureVerificationKey;
import com.kloudtek.kryptotek.key.SigningKey;
import com.kloudtek.util.StringUtils;

import javax.ws.rs.WebApplicationException;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.logging.Level;
import java.util.logging.Logger;

import static javax.ws.rs.core.Response.Status.INTERNAL_SERVER_ERROR;
import static javax.ws.rs.core.Response.Status.UNAUTHORIZED;

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
        SignatureVerificationKey key = findVerificationKey(identity);
        if (key == null) {
            return false;
        }
        try {
            CryptoUtils.verifySignature(key, digestAlgorithm, dataToSign, StringUtils.base64Decode(signature));
            return true;
        } catch (InvalidKeyException e) {
            logger.log(Level.SEVERE, "Invalid key found while verifying signature: " + e.getMessage(), e);
            throw new WebApplicationException(INTERNAL_SERVER_ERROR);
        } catch (SignatureException e) {
            return false;
        }
    }

    @Override
    protected String signResponse(String identity, byte[] data) throws InvalidKeyException {
        SigningKey key = findSigningKey(identity);
        if (key == null) {
            logger.severe("Unable to find key for response signing: "+identity);
            throw new WebApplicationException(UNAUTHORIZED);
        }
        return StringUtils.base64Encode(CryptoUtils.sign(key, digestAlgorithm, data));
    }

    protected abstract SigningKey findSigningKey(String identity);

    protected abstract SignatureVerificationKey findVerificationKey(String identity);
}
