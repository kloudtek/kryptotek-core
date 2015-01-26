/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.key;

/**
 * Key types
 */
public enum KeyType {
    AES, HMAC_SHA1, HMAC_SHA256, HMAC_SHA512, RSA_PUBLIC, RSA_PRIVATE, RSA_KEYPAIR, CERT_SIMPLE,
    CERT_X509, DH_PUBLIC, DH_PRIVATE, DH_KEYPAIR
}
