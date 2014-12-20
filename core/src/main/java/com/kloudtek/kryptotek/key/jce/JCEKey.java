/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.key.jce;

/**
 * Created by yannick on 19/12/2014.
 */
public interface JCEKey {
    String getJceCryptAlgorithm(boolean compatibilityMode);
}
