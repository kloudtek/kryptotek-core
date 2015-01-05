/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek;

import org.testng.Assert;
import org.testng.annotations.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import static com.kloudtek.kryptotek.SymmetricAlgorithm.AES;

/**
 * Created by yannick on 15/02/2014.
 */
public class CryptoUtilsTest {
    @Test
    public void testSplitKey() throws UnsupportedEncodingException {
        String data = "hello world";
        byte[][] keys = CryptoUtils.splitKey(data.getBytes("UTF-8"), 4);
        byte[] merged = CryptoUtils.mergeSplitKey(keys[0], keys[1], keys[2], keys[3]);
        Assert.assertEquals(new String(merged), data);
        merged = CryptoUtils.mergeSplitKey(keys[3], keys[0], keys[1], keys[2]);
        Assert.assertEquals(new String(merged), data);
        merged = CryptoUtils.mergeSplitKey(keys[3], keys[2], keys[1], keys[0]);
        Assert.assertEquals(new String(merged), data);
    }

    /**
     * Change a random byte of the specified data
     *
     * @param data Data to scramble
     */
    private void scrambleByte(byte[] data) {
        int idx = new SecureRandom().nextInt(data.length);
        data[idx] = (byte) (data[idx] - 1);
        if (data[idx] < 0) {
            data[idx] = 50;
        }
    }

    private static byte[] getRandomData() {
        return getRandomData(1000000);
    }

    private static byte[] getRandomData(int size) {
        byte[] data = new byte[size];
        new SecureRandom().nextBytes(data);
        return data;
    }
}
