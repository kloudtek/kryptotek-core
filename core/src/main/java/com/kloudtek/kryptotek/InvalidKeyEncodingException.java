/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek;

import com.kloudtek.ktserializer.Serializable;

/**
 * Created by yannick on 30/12/2014.
 */
public class InvalidKeyEncodingException extends Exception {
    private static final long serialVersionUID = -592603548577709630L;

    public InvalidKeyEncodingException() {
    }

    public InvalidKeyEncodingException(EncodedKey.Format format) {
        super("Encoding format "+format.name()+" not supported by key");
    }

    public InvalidKeyEncodingException(String detailMessage) {
        super(detailMessage);
    }

    public InvalidKeyEncodingException(String detailMessage, Throwable throwable) {
        super(detailMessage, throwable);
    }

    public InvalidKeyEncodingException(Throwable throwable) {
        super(throwable);
    }
}
