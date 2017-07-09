/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek;

import java.util.Arrays;

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

    public String getFingerprint() {
        return CryptoUtils.fingerprint(encodedKey);
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

    public static void checkSupportedFormat( Format format, Format... supportedFormats ) throws InvalidKeyEncodingException {
        for (Format supportedFormat : supportedFormats) {
            if( supportedFormat.equals(format) ) {
                return;
            }
        }
        throw new InvalidKeyEncodingException(format);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        EncodedKey that = (EncodedKey) o;

        if (!Arrays.equals(encodedKey, that.encodedKey)) return false;
        if (format != that.format) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(encodedKey);
        result = 31 * result + format.hashCode();
        return result;
    }

    public enum Format {
        RAW, PKCS8, X509, SERIALIZED
    }
}
