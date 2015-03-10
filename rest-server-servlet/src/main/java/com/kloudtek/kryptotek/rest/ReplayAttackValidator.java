/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.rest;

/**
 * Created by yannick on 10/03/2015.
 */
public interface ReplayAttackValidator {
    boolean checkNounceReplay(String nounce);
}
