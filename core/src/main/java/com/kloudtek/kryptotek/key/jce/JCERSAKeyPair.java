/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.key.jce;

import com.kloudtek.kryptotek.EncodedKey;
import com.kloudtek.kryptotek.InvalidKeyEncodingException;
import com.kloudtek.kryptotek.JCECryptoEngine;
import com.kloudtek.kryptotek.key.RSAKeyPair;
import com.kloudtek.ktserializer.*;
import com.kloudtek.util.UnexpectedException;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by yannick on 18/12/2014.
 */
public class JCERSAKeyPair extends JCEKeyPair<JCERSAPublicKey,JCERSAPrivateKey> implements JCERSAKey, RSAKeyPair<JCERSAPublicKey,JCERSAPrivateKey> {
    public JCERSAKeyPair(JCECryptoEngine cryptoEngine, KeyPair keyPair) {
        super(cryptoEngine, keyPair);
        privateKey = new JCERSAPrivateKey(cryptoEngine, keyPair.getPrivate());
        publicKey = new JCERSAPublicKey(cryptoEngine, keyPair.getPublic());
    }

    public JCERSAKeyPair(JCECryptoEngine cryptoEngine, EncodedKey encodedKey) throws InvalidKeyException, InvalidKeyEncodingException {
        super(cryptoEngine, encodedKey);
    }

    public JCERSAKeyPair(JCECryptoEngine cryptoEngine, byte[] serializedKeyPair) throws InvalidKeyException {
        super(cryptoEngine);
        try {
            Serializer.deserialize(this,serializedKeyPair);
        } catch (InvalidSerializedDataException e) {
            throw new InvalidKeyException(e);
        }
    }

    @Override
    public int getVersion() {
        return 0;
    }

    @Override
    public void serialize(@NotNull SerializationStream os) throws IOException {
        os.writeData(keyPair.getPrivate().getEncoded());
        os.write(keyPair.getPublic().getEncoded());
    }

    @Override
    public void deserialize(@NotNull DeserializationStream is, int version) throws IOException, InvalidSerializedDataException {
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(is.readData()));
            PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(is.readRemaining()));
            keyPair = new KeyPair(publicKey, privateKey);
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedException(e);
        } catch (InvalidKeySpecException e) {
            throw new InvalidSerializedDataException(e);
        }
    }

    @Override
    public String getJceCryptAlgorithm(boolean compatibilityMode) {
        return JCECryptoEngine.getRSAEncryptionAlgorithm(compatibilityMode);
    }
}
