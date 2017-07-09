/*
 * Copyright (c) 2016 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.jce;

import com.kloudtek.kryptotek.Key;
import com.kloudtek.ktserializer.Serializable;

/**
 * Created by yannick on 19/12/2014.
 */
public interface JCEKey extends Key, Serializable {
    String getJceCryptAlgorithm(boolean compatibilityMode);
}
