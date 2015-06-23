/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.key;

/**
 * Created by yannick on 23/06/15.
 */
public enum AESKeyLen {
    AES128(128), AES192(192), AES256(256);
    private int lenBits;
    private int lenBytes;

    AESKeyLen(int lenBits) {
        this.lenBits = lenBits;
        this.lenBytes = lenBits / 8;
    }

    public static AESKeyLen getByBitLen( int bitLen ) {
        for (AESKeyLen keyLen : values()) {
            if( keyLen.getLenBits() == bitLen ) {
                return keyLen;
            }
        }
        throw new IllegalArgumentException("Invalid AES key size: "+bitLen);
    }

    public int getLenBits() {
        return lenBits;
    }

    public int getLenBytes() {
        return lenBits;
    }
}
