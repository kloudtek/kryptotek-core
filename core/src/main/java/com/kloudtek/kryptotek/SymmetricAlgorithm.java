/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek;

/**
 * Created by yannick on 09/11/13.
 */
public enum SymmetricAlgorithm {
    AES(Key.Type.AES);
    private String jceId;
    private Key.Type keyType;

    SymmetricAlgorithm(Key.Type keyType) {
        this.keyType = keyType;
        jceId = name();
    }

    SymmetricAlgorithm(String jceId, Key.Type keyType) {
        this.keyType = keyType;
        this.jceId = jceId != null ? jceId : name();
    }

    public String getJceId() {
        return jceId;
    }

    public Key.Type getKeyType() {
        return keyType;
    }
}
