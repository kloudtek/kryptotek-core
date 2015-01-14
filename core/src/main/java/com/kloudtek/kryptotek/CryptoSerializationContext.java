/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek;

import com.kloudtek.ktserializer.SerializationContext;

/**
 * Created by yannick on 02/01/2015.
 */
public class CryptoSerializationContext extends SerializationContext {
    public CryptoSerializationContext( SerializationContext parent, CryptoEngine cryptoEngine ) {
        super(parent);
        set(CryptoEngine.class, cryptoEngine);
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
