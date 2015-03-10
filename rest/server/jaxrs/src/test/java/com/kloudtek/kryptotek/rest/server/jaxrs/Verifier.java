/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.rest.server.jaxrs;

import com.kloudtek.kryptotek.DigestAlgorithm;
import com.kloudtek.kryptotek.key.SignatureVerificationKey;
import com.kloudtek.kryptotek.key.SigningKey;

import java.util.logging.Logger;

/**
 * Created by yannick on 29/10/2014.
 */
public class Verifier extends RESTAuthenticationFilter {
    private static final Logger logger = Logger.getLogger(Verifier.class.getName());
    private DigestAlgorithm digestAlgorithm;

    public Verifier() {
        this.digestAlgorithm = DigestAlgorithm.SHA1;
    }

    protected SigningKey findSigningKey(String identity) {
        if (identity.equals(RESTAuthenticationFilterTest.USER)) {
            return RESTAuthenticationFilterTest.HMAC_KEY;
        } else {
            return null;
        }
    }

    protected SignatureVerificationKey findVerificationKey(String identity) {
        if (identity.equals(RESTAuthenticationFilterTest.USER)) {
            return RESTAuthenticationFilterTest.HMAC_KEY;
        } else {
            return null;
        }
    }
}
