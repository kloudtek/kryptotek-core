/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.keystore;

import com.kloudtek.util.dao.DataAccessException;

/**
 * Created by yannick on 22/11/2014.
 */
public class KeyStoreAccessException extends DataAccessException {
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
