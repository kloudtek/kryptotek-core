/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.key;

/**
 * Created by yannick on 26/01/2015.
 */
public interface DHKeyPair<B extends DHPublicKey, V extends DHPrivateKey> extends RSAKey, KeyPair<B, V> {
}
