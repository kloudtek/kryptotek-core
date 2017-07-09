/*
 * Copyright (c) 2016 Kloudtek Ltd
 */

package com.kloudtek.kryptotek;

/**
 * Created by yannick on 12/4/16.
 */
public class DecryptionException extends Exception {
    public DecryptionException() {
    }

    public DecryptionException(String message) {
        super(message);
    }

    public DecryptionException(String message, Throwable cause) {
        super(message, cause);
    }

    public DecryptionException(Throwable cause) {
        super(cause);
    }
}
