/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.key.jce;

import com.kloudtek.kryptotek.*;
import com.kloudtek.kryptotek.key.KeyPair;
import com.kloudtek.kryptotek.key.PrivateKey;
import com.kloudtek.kryptotek.key.PublicKey;
import com.kloudtek.ktserializer.*;
import com.kloudtek.util.UnexpectedException;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.security.InvalidKeyException;

import static com.kloudtek.kryptotek.EncodedKey.Format.SERIALIZED;

/**
 * Created by yannick on 18/12/2014.
 */
public abstract class JCEKeyPair<B extends PublicKey,V extends PrivateKey> extends AbstractCustomSerializable implements JCEKey, KeyPair<B,V> {
    protected JCECryptoEngine cryptoEngine;
    protected java.security.KeyPair keyPair;
    protected B publicKey;
    protected V privateKey;

    protected JCEKeyPair(JCECryptoEngine cryptoEngine) {
        this.cryptoEngine = cryptoEngine;
    }

    protected JCEKeyPair(JCECryptoEngine cryptoEngine, java.security.KeyPair keyPair) {
        this.cryptoEngine = cryptoEngine;
        this.keyPair = keyPair;
    }

    protected JCEKeyPair(JCECryptoEngine cryptoEngine, EncodedKey encodedKey) throws InvalidKeyException, InvalidKeyEncodingException {
        this.cryptoEngine = cryptoEngine;
        if( encodedKey.getFormat() != SERIALIZED ) {
            throw new InvalidKeyEncodingException(encodedKey.getFormat());
        }
        try {
            Serializer.deserialize(this,encodedKey.getEncodedKey());
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
        return new EncodedKey(serialize(new CryptoSerializationContext(cryptoEngine)), SERIALIZED);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        JCEKeyPair that = (JCEKeyPair) o;

        if (cryptoEngine != null ? !cryptoEngine.equals(that.cryptoEngine) : that.cryptoEngine != null) return false;
        if (keyPair != null ? !keyPair.equals(that.keyPair) : that.keyPair != null) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = cryptoEngine != null ? cryptoEngine.hashCode() : 0;
        result = 31 * result + (keyPair != null ? keyPair.hashCode() : 0);
        return result;
    }
}
