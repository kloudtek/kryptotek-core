/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.jce;

import com.kloudtek.kryptotek.EncodedKey;
import com.kloudtek.kryptotek.InvalidKeyEncodingException;
import com.kloudtek.kryptotek.key.DHKeyPair;
import com.kloudtek.kryptotek.key.KeyType;
import com.kloudtek.kryptotek.key.RSAKeyPair;
import com.kloudtek.ktserializer.DeserializationStream;
import com.kloudtek.ktserializer.InvalidSerializedDataException;
import com.kloudtek.ktserializer.SerializationStream;
import com.kloudtek.util.UnexpectedException;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by yannick on 26/01/2015.
 */
public class JCEDHKeyPair extends JCEKeyPair<JCEDHPublicKey,JCEDHPrivateKey> implements JCERSAKey, DHKeyPair<JCEDHPublicKey,JCEDHPrivateKey> {
    public JCEDHKeyPair() {
    }

    public JCEDHKeyPair(JCECryptoEngine cryptoEngine, KeyPair keyPair) {
        super(cryptoEngine, keyPair);
        privateKey = new JCEDHPrivateKey(cryptoEngine, keyPair.getPrivate());
        publicKey = new JCEDHPublicKey(cryptoEngine, keyPair.getPublic());
    }

    public JCEDHKeyPair(JCECryptoEngine cryptoEngine, EncodedKey encodedKey) throws InvalidKeyException, InvalidKeyEncodingException {
        super(cryptoEngine, encodedKey);
    }

    public JCEDHKeyPair(JCECryptoEngine cryptoEngine, byte[] serializedKeyPair) throws InvalidKeyException {
        super(cryptoEngine);
        try {
            cryptoEngine.serializer.deserialize(this, serializedKeyPair);
        } catch (InvalidSerializedDataException e) {
            throw new InvalidKeyException(e);
        }
    }

    @Override
    public KeyType getType() {
        return KeyType.RSA_KEYPAIR;
    }

    @Override
    public void serialize(@NotNull SerializationStream os) throws IOException {
        os.writeData(keyPair.getPrivate().getEncoded());
        os.write(keyPair.getPublic().getEncoded());
    }

    @Override
    public void deserialize(@NotNull DeserializationStream is, int version) throws IOException, InvalidSerializedDataException {
        try {
            KeyFactory kf = KeyFactory.getInstance("DH");
            PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(is.readData()));
            PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(is.readRemaining()));
            keyPair = new KeyPair(publicKey, privateKey);
            super.privateKey = new JCEDHPrivateKey(cryptoEngine, privateKey);
            super.publicKey = new JCEDHPublicKey(cryptoEngine, publicKey);
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedException(e);
        } catch (InvalidKeySpecException e) {
            throw new InvalidSerializedDataException(e);
        }
    }

    @Override
    public String getJceCryptAlgorithm(boolean compatibilityMode) {
        return null;
    }
}
