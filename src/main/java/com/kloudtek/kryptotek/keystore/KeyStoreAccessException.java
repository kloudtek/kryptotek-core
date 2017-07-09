/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.keystore;

import com.kloudtek.util.BackendAccessException;

/**
 * Created by yannick on 22/11/2014.
 */
public class KeyStoreAccessException extends BackendAccessException {
    public KeyStoreAccessException() {
    }

    public KeyStoreAccessException(String message) {
        super(message);
    }

    public KeyStoreAccessException(String message, Throwable cause) {
        super(message, cause);
    }

    public KeyStoreAccessException(Throwable cause) {
        super(cause);
    }
}
