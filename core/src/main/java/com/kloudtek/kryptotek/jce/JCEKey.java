/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.jce;

import com.kloudtek.kryptotek.Key;
import org.jetbrains.annotations.NotNull;

/**
 * Created by yannick on 19/12/2014.
 */
public interface JCEKey extends Key {
    void setCryptoEngine(@NotNull JCECryptoEngine cryptoEngine);
    String getJceCryptAlgorithm(boolean compatibilityMode);
}
