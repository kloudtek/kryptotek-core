/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.jce;

import com.kloudtek.kryptotek.Key;

/**
 * Created by yannick on 19/12/2014.
 */
public interface JCEKey extends Key {
    String getJceCryptAlgorithm(boolean compatibilityMode);
}
