/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek;

import com.kloudtek.kryptotek.key.KeyType;
import com.kloudtek.ktserializer.Serializable;

/**
 * Created by yannick on 22/11/2014.
 */
public interface Key extends Serializable {
    KeyType getType();

    /**
     * Return the key in encoded format, using the key's default encoding type (which depends on the key and engine).
     * @return encoded key, or null if no encoded key is supported
     */
    EncodedKey getEncoded();

    /**
     * Return the key in encoded format, using the key's default encoding type
     */
    EncodedKey getEncoded( EncodedKey.Format format ) throws InvalidKeyEncodingException;

    byte[] serialize();

    /**
     * Destroy all key data from memory
     */
    void destroy();

    /**
     * Get the engine that created this key
     * @return {@link com.kloudtek.kryptotek.CryptoEngine} implementation
     */
    CryptoEngine getCryptoEngine();
}
