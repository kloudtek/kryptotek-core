/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.key;

import java.math.BigInteger;

/**
 * Created by yannick on 26/01/2015.
 */
public class DHParameters {
    private BigInteger p;
    private BigInteger g;
    private int l;

    public DHParameters(BigInteger p, BigInteger g) {
        this.p = p;
        this.g = g;
        this.l = 0;
    }

    public DHParameters(BigInteger p, BigInteger g, int l) {
        this.p = p;
        this.g = g;
        this.l = l;
    }

    public BigInteger getP() {
        return this.p;
    }

    public BigInteger getG() {
        return this.g;
    }

    public int getL() {
        return this.l;
    }
}
