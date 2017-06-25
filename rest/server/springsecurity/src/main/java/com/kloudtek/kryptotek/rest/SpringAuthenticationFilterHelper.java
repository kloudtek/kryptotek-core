package com.kloudtek.kryptotek.rest;

import com.kloudtek.kryptotek.CryptoEngine;
import com.kloudtek.kryptotek.DigestAlgorithm;
import com.kloudtek.kryptotek.key.SignatureVerificationKey;
import com.kloudtek.kryptotek.key.SigningKey;
import com.kloudtek.util.BackendAccessException;

import javax.servlet.ServletRequest;
import java.io.InputStream;
import java.security.Principal;

/**
 * Spring Security authentication filter helper
 */
public class SpringAuthenticationFilterHelper extends AuthenticationFilterHelper<Principal, ServletRequest> {
    public SpringAuthenticationFilterHelper() {
    }

    public SpringAuthenticationFilterHelper(CryptoEngine cryptoEngine) {
        super(cryptoEngine);
    }

    public SpringAuthenticationFilterHelper(CryptoEngine cryptoEngine, ReplayAttackValidator replayAttackValidator) {
        super(cryptoEngine, replayAttackValidator);
    }

    public SpringAuthenticationFilterHelper(CryptoEngine cryptoEngine, Long contentMaxSize, DigestAlgorithm digestAlgorithm, long expiry, ReplayAttackValidator replayAttackValidator) {
        super(cryptoEngine, contentMaxSize, digestAlgorithm, expiry, replayAttackValidator);
    }

    @Override
    protected void replaceDataStream(ServletRequest requestObj, InputStream inputStream) {

    }

    @Override
    protected Principal findUserPrincipal(String identity) {
        return null;
    }

    @Override
    protected SignatureVerificationKey findVerificationKey(Principal principal) throws BackendAccessException {
        return null;
    }

    @Override
    protected SigningKey findSigningKey(Principal principal) throws BackendAccessException {
        return null;
    }
}
