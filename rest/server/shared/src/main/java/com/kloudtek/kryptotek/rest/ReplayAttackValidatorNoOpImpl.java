/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.rest;

/**
 * Created by yannick on 10/03/2015.
 */
public class ReplayAttackValidatorNoOpImpl implements ReplayAttackValidator {
    @Override
    public boolean checkNounceReplay(String nounce) {
        return false;
    }
}
