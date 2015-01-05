/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.key.jce;

import com.kloudtek.kryptotek.*;
import com.kloudtek.ktserializer.*;
import org.jetbrains.annotations.NotNull;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.logging.Level;
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
                logger.log(Level.WARNING, "Unable to destroy key: " + e.getMessage(), e);
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
        if(( defaultEncoding != null && defaultEncoding == format) || format == EncodedKey.Format.SERIALIZED) {
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
