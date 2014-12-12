/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek;

/**
 * Created by yannick on 22/11/2014.
 */
public interface Key {
    CryptoAlgorithm getAlgorithm();

    boolean isEncryptionKey();

    boolean isDecryptionKey();

    boolean isSigningKey();

    boolean isSignatureVerificationKey();

    public enum Type {
        RSA_KEY_AND_CERT
    }
}
