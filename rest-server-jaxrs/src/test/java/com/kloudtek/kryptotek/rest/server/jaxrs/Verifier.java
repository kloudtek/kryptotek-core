/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.rest.server.jaxrs;

import com.kloudtek.kryptotek.DigestAlgorithm;

import javax.crypto.SecretKey;

/**
 * Created by yannick on 29/10/2014.
 */
public class Verifier extends HmacJAXRSServerSignatureVerifier {
    public Verifier() {
        super(DigestAlgorithm.SHA1);
    }

    @Override
    protected SecretKey findKey(String identity) {
        if( identity.equals(JAXRSServerSignatureVerifierTest.USER) ) {
            return JAXRSServerSignatureVerifierTest.HMAC_KEY;
        } else {
            return null;
        }
    }
}
