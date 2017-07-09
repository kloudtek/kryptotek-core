/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.keystore;

/**
 * Created by yannick on 22/11/2014.
 */
public class CredentialInvalidException extends Exception {
    public CredentialInvalidException() {
    }

    public CredentialInvalidException(String detailMessage) {
        super(detailMessage);
    }

    public CredentialInvalidException(String detailMessage, Throwable throwable) {
        super(detailMessage, throwable);
    }

    public CredentialInvalidException(Throwable throwable) {
        super(throwable);
    }
}
