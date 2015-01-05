/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.key;

import com.kloudtek.kryptotek.Key;

/**
 * Created by yannick on 20/12/2014.
 */
public interface KeyPair<B extends PublicKey, V extends PrivateKey> extends Key {
    B getPublicKey();
    V getPrivateKey();
}
