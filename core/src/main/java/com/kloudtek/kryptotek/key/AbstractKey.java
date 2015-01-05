/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.key;

import com.kloudtek.kryptotek.CryptoAlgorithm;
import com.kloudtek.kryptotek.CryptoEngine;
import com.kloudtek.kryptotek.Key;

/**
 * Created by yannick on 18/12/2014.
 */
public abstract class AbstractKey implements Key {
    private CryptoEngine cryptoEngine;

    protected AbstractKey(CryptoEngine cryptoEngine) {
        this.cryptoEngine = cryptoEngine;
    }

    @Override
    public CryptoEngine getCryptoEngine() {
        return null;
    }
}
