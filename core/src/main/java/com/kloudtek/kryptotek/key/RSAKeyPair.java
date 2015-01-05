/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.key;

import com.kloudtek.kryptotek.Key;

import java.security.*;

/**
 * Created by yannick on 18/12/2014.
 */
public interface RSAKeyPair<B extends RSAPublicKey, V extends RSAPrivateKey> extends RSAKey, KeyPair<B, V>, EncryptionKey, DecryptionKey, SignAndVerifyKey {
    B getPublicKey();
    V getPrivateKey();
}
