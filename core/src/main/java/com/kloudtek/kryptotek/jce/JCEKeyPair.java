/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.jce;

import com.kloudtek.kryptotek.CryptoEngine;
import com.kloudtek.kryptotek.EncodedKey;
import com.kloudtek.kryptotek.InvalidKeyEncodingException;
import com.kloudtek.kryptotek.key.KeyPair;
import com.kloudtek.kryptotek.key.PrivateKey;
import com.kloudtek.kryptotek.key.PublicKey;
import com.kloudtek.ktserializer.AbstractCustomSerializable;
import com.kloudtek.ktserializer.InvalidSerializedDataException;
import com.kloudtek.util.UnexpectedException;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.security.InvalidKeyException;

import static com.kloudtek.kryptotek.EncodedKey.Format.SERIALIZED;

/**
 * Created by yannick on 18/12/2014.
 */
public abstract class JCEKeyPair<V extends PrivateKey, B extends PublicKey> extends AbstractCustomSerializable implements JCEKey, KeyPair {
    protected JCECryptoEngine cryptoEngine;
    protected java.security.KeyPair keyPair;
    protected B publicKey;
    protected V privateKey;

    protected JCEKeyPair() {
    }

    protected JCEKeyPair(@NotNull JCECryptoEngine cryptoEngine) {
        this.cryptoEngine = cryptoEngine;
    }

    protected JCEKeyPair(@NotNull JCECryptoEngine cryptoEngine, java.security.KeyPair keyPair) {
        this.cryptoEngine = cryptoEngine;
        this.keyPair = keyPair;
    }

    protected JCEKeyPair(@NotNull JCECryptoEngine cryptoEngine, EncodedKey encodedKey) throws InvalidKeyException, InvalidKeyEncodingException {
        this.cryptoEngine = cryptoEngine;
        if( encodedKey.getFormat() != SERIALIZED ) {
            throw new InvalidKeyEncodingException(encodedKey.getFormat());
        }
        try {
            cryptoEngine.serializer.deserialize(this, encodedKey.getEncodedKey());
        } catch (InvalidSerializedDataException e) {
            throw new InvalidKeyException(e);
        }
    }

    public java.security.KeyPair getJCEKeyPair() {
        return keyPair;
    }

    @Override
    public V getPrivateKey() {
        return privateKey;
    }

    @Override
    public B getPublicKey() {
        return publicKey;
    }

    @Override
    public void destroy() {
        publicKey.destroy();
        privateKey.destroy();
    }

    @Override
    public CryptoEngine getCryptoEngine() {
        return cryptoEngine;
    }

    @Override
    public void setCryptoEngine(@NotNull JCECryptoEngine cryptoEngine) {
        this.cryptoEngine = cryptoEngine;
    }

    @Nullable
    @Override
    public EncodedKey getEncoded() {
        try {
            return getEncoded(SERIALIZED);
        } catch (InvalidKeyEncodingException e) {
            throw new UnexpectedException(e);
        }
    }

    @Override
    public EncodedKey getEncoded(EncodedKey.Format format) throws InvalidKeyEncodingException {
        EncodedKey.checkSupportedFormat(format, SERIALIZED);
        final byte[] serializedData = serialize();
        return new EncodedKey(serializedData, SERIALIZED);
    }

    @Override
    public byte[] serialize() {
        return cryptoEngine.serializer.serialize(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        JCEKeyPair that = (JCEKeyPair) o;

        if (!privateKey.equals(that.privateKey)) return false;
        return publicKey.equals(that.publicKey);

    }

    @Override
    public int hashCode() {
        int result = publicKey.hashCode();
        result = 31 * result + privateKey.hashCode();
        return result;
    }
}
