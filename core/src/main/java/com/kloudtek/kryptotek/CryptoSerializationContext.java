/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek;

import com.kloudtek.kryptotek.key.jce.JCEAESKey;
import com.kloudtek.kryptotek.key.jce.JCEHMACSHA1Key;
import com.kloudtek.kryptotek.key.jce.JCEHMACSHA256Key;
import com.kloudtek.kryptotek.key.jce.JCEHMACSHA512Key;
import com.kloudtek.ktserializer.ClassMapper;
import com.kloudtek.ktserializer.SerializationContext;

/**
 * Created by yannick on 02/01/2015.
 */
public class CryptoSerializationContext extends SerializationContext {
    public static final Integer SERIALIZATION_VERSION = 1;

    public CryptoSerializationContext( SerializationContext parent, CryptoEngine cryptoEngine ) {
        super(parent);
        version = SERIALIZATION_VERSION;
        set(cryptoEngine);
    }

    public CryptoSerializationContext() {
        this(null,CryptoUtils.engine);
    }

    public CryptoSerializationContext( SerializationContext parent ) {
        this(parent,CryptoUtils.engine);
    }

    public CryptoSerializationContext( CryptoEngine cryptoEngine ) {
        this(null,cryptoEngine);
    }

    public CryptoEngine getCryptoEngine() {
        return get(CryptoEngine.class);
    }
}
