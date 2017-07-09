/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.key;

import com.kloudtek.kryptotek.DigestAlgorithm;

/**
 * Created by yannick on 18/12/2014.
 */
public interface HMACKey extends SymmetricKey, SignAndVerifyKey {
    DigestAlgorithm getDigestAlgorithm();
}
