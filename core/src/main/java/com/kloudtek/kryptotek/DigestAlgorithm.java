/*
 * Copyright (c) 2016 Kloudtek Ltd
 */

package com.kloudtek.kryptotek;


/**
 * Enumeration of digest algorithms
 */
public enum DigestAlgorithm {
    // DO NOT CHANGE ORDER, ordinal() is used in various serialization !!!!!!
    MD5(16, 64), SHA1(20, 64, "SHA-1"), SHA256(32, 32, "SHA-256"),
    SHA512(64, 64, "SHA-512");
    private int hashLen;
    private int hmacKeyLen;
    private String jceId;

    DigestAlgorithm(int hashLen, int hmacKeyLen) {
        init(hashLen, hmacKeyLen, name());
    }

    DigestAlgorithm(int hashLen, int hmacKeyLen, String jceId) {
        init(hashLen, hmacKeyLen, jceId);
    }

    private void init(int hashLen, int hmacKeyLen, String jceId) {
        this.hashLen = hashLen;
        this.hmacKeyLen = hmacKeyLen;
        this.jceId = jceId;
    }

    public String getJceId() {
        return jceId;
    }

    public int getHashLen() {
        return hashLen;
    }

    public int getHmacKeyLen() {
        return hmacKeyLen;
    }

    public static DigestAlgorithm get(String id) {
        id = id.toUpperCase();
        for (DigestAlgorithm alg : values()) {
            if (id.endsWith(alg.jceId) || id.endsWith(alg.name())) {
                return alg;
            }
        }
        return null;
    }
}
