/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.key.jce;

import com.kloudtek.kryptotek.CryptoEngine;
import com.kloudtek.kryptotek.EncodedKey;
import com.kloudtek.kryptotek.InvalidKeyEncodingException;
import com.kloudtek.kryptotek.JCECryptoEngine;
import com.kloudtek.ktserializer.*;
import org.jetbrains.annotations.NotNull;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.logging.Logger;

/**
 * Created by yannick on 20/12/2014.
 */
public abstract class AbstractJCEKey<K extends java.security.Key> extends AbstractCustomSerializable implements JCEKey, CustomSerializable {
    private static final Logger logger = Logger.getLogger(AbstractJCEKey.class.getName());
    private JCECryptoEngine cryptoEngine;
    protected K key;

    protected AbstractJCEKey(JCECryptoEngine cryptoEngine) {
        this.cryptoEngine = cryptoEngine;
    }

    protected AbstractJCEKey(JCECryptoEngine cryptoEngine, K key) {
        this.cryptoEngine = cryptoEngine;
        this.key = key;
    }

    protected AbstractJCEKey(JCECryptoEngine cryptoEngine, EncodedKey encodedKey) throws InvalidKeyException, InvalidKeyEncodingException {
        this.cryptoEngine = cryptoEngine;
        readEncodedKey(encodedKey);
    }

    protected void readEncodedKey(EncodedKey encodedKey) throws InvalidKeyException, InvalidKeyEncodingException {
        if( encodedKey.getFormat() == EncodedKey.Format.SERIALIZED || encodedKey.getFormat() == getDefaultEncoding() ) {
            setDefaultEncoded(encodedKey.getEncodedKey());
        } else {
            throw new InvalidKeyEncodingException(encodedKey.getFormat());
        }
    }

    @Override
    public void destroy() {
        if (key instanceof Destroyable && !((Destroyable) key).isDestroyed()) {
            try {
                ((Destroyable) key).destroy();
            } catch (DestroyFailedException e) {
                // it's too common that JCE keys aren't destroyable although they say they are
                // so won't log this to avoid spamming logs
            }
        }
    }

    @Override
    public EncodedKey getEncoded() {
        return new EncodedKey(getDefaultEncoded(), getDefaultEncoding());
    }

    @Override
    public EncodedKey getEncoded(EncodedKey.Format format) throws InvalidKeyEncodingException {
        EncodedKey.Format defaultEncoding = getDefaultEncoding();
        if (format == EncodedKey.Format.SERIALIZED) {
            byte[] encoded = getDefaultEncoded();
            byte[] serialized = new byte[encoded.length + 1];
            encoded[0] = (byte) getType().ordinal();
            System.arraycopy(encoded, 0, serialized, 1, encoded.length);
            return new EncodedKey(serialized, EncodedKey.Format.SERIALIZED);
        } else if ((defaultEncoding != null && defaultEncoding == format)) {
            return new EncodedKey(getDefaultEncoded(),format);
        } else {
            throw new InvalidKeyEncodingException(format);
        }
    }

    @Override
    public CryptoEngine getCryptoEngine() {
        return cryptoEngine;
    }

    @Override
    public String getJceCryptAlgorithm(boolean compatibilityMode) {
        return null;
    }


    @Override
    public int getVersion() {
        return 0;
    }

    @Override
    public void deserialize(@NotNull DeserializationStream is, int version) throws IOException, InvalidSerializedDataException {
        try {
            setDefaultEncoded(is.readRemaining());
        } catch (InvalidKeyException e) {
            throw new InvalidSerializedDataException(e);
        }
    }

    @Override
    public void serialize(@NotNull SerializationStream os) throws IOException {
        os.write(getDefaultEncoded());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        AbstractJCEKey that = (AbstractJCEKey) o;

        if (!key.equals(that.key)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        return key.hashCode();
    }

    public abstract EncodedKey.Format getDefaultEncoding();

    public abstract void setDefaultEncoded(byte[] encodedKey) throws InvalidKeyException;

    public abstract byte[] getDefaultEncoded();
}
