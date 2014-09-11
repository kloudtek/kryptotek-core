/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek;

import com.kloudtek.util.ArrayUtils;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static com.kloudtek.kryptotek.DigestAlgorithm.SHA1;
import static org.testng.Assert.*;

public class DigestUtilsTest {
    @Test
    public void testSSHA() {
        byte[] data = "HelloWorldThisIsADigestToEncode@#$gfms8i23o5m*T)6y891'".getBytes();
        byte[] digest = DigestUtils.digest(data, SHA1);
        Assert.assertTrue(DigestUtils.compareSaltedDigest(digest, data, SHA1));
        Assert.assertFalse(DigestUtils.compareSaltedDigest(digest, "sfaiofdsadjiofsadjiosafjasfdo".getBytes(), SHA1));
    }

    @Test
    public void testSSHABase64() {
        String data = "HelloWorldThisIsADigestToEncode@#$gfms8i23o5m*T)6y891'";
        String digest = DigestUtils.saltedB64Digest(data, SHA1);
        Assert.assertTrue(DigestUtils.compareSaltedDigest(digest, data, SHA1));
        Assert.assertFalse(DigestUtils.compareSaltedDigest(digest, "sfaiofdsadjiofsadjiosafjasfdo", SHA1));
    }

    @Test
    public void testCompareGeneratedBase64() {
        String value = "ASfdasfdfsdafsdajfsdaljfdslakjfsadkjf";
        String cryptedSaltedValue = DigestUtils.saltedB64Digest(value, SHA1);
        Assert.assertTrue(DigestUtils.compareSaltedDigest(cryptedSaltedValue, value, SHA1));
    }

    @Test
    public void createSHADigestFromStream() throws NoSuchAlgorithmException, IOException {
        byte[] value = "afdsfsdafasdafdsasfdsa".getBytes();
        byte[] digest = MessageDigest.getInstance("SHA-1").digest(value);
        assertEquals(DigestUtils.digest(new ByteArrayInputStream(value), SHA1), digest);
    }

    @Test
    public void testSaltedDigest(){
        byte[] data = ArrayUtils.toBytes("Password".toCharArray());
        byte[] value = DigestUtils.saltedDigest(data, SHA1);
        String s = new String(value);
        System.out.println("s = " + s);

        boolean b = DigestUtils.compareSaltedDigest(value, data, SHA1);
        System.out.println("b = " + b);
    }
}
