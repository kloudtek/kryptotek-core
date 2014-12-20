/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.key;

import com.kloudtek.kryptotek.Key;

/**
 * A certificate contains a key and extra information in regards to the owner of that key
 */
public interface Certificate extends Key {
    String getSubject();

    byte[] getSubjectKeyIdentifier();
}
