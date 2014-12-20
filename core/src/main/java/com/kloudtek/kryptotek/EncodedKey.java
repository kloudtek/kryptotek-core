/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek;

/**
 * Created by yannick on 18/12/2014.
 */
public class EncodedKey {
    private byte[] encodedKey;
    private Format format;

    public EncodedKey(byte[] encodedKey, Format format) {
        this.encodedKey = encodedKey;
        this.format = format;
    }

    public byte[] getEncodedKey() {
        return encodedKey;
    }

    public Format getFormat() {
        return format;
    }

    public static EncodedKey aesRaw(byte[] encodedKey) {
        return new EncodedKey(encodedKey, Format.RAW);
    }

    public static EncodedKey hmacRaw(byte[] encodedKey) {
        return new EncodedKey(encodedKey, Format.RAW);
    }

    public static EncodedKey rsaPrivatePkcs8(byte[] encodedKey) {
        return new EncodedKey(encodedKey, Format.PKCS8);
    }

    public static EncodedKey rsaPublicX509(byte[] encodedKey) {
        return new EncodedKey(encodedKey, Format.X509);
    }

    public enum Format {
        RAW, PKCS8, X509, CUSTOM
    }
}
