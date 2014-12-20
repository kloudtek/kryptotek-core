/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek;

/**
 * Created by yannick on 22/11/2014.
 */
public interface Key {
    Type getType();

    CryptoAlgorithm getAlgorithm();

    boolean isEncryptionKey();

    boolean isDecryptionKey();

    boolean isSigningKey();

    boolean isSignatureVerificationKey();

    EncodedKey getEncoded();

    void destroy();

    public enum Type {
        X509_CERT, RSA_KEYPAIR, RSA_PUBLIC, RSA_PRIVATE, HMAC_SHA1, HMAC_SHA256, HMAC_SHA512, AES
    }
}
