/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.key;

import com.kloudtek.kryptotek.Key;

import java.security.*;

/**
 * Created by yannick on 18/12/2014.
 */
public interface RSAKeyPair extends RSAKey, KeyPair, EncryptionKey, DecryptionKey, SignAndVerifyKey {
    RSAPublicKey getPublicKey();
    RSAPrivateKey getPrivateKey();
}
