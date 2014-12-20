/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.key.jce;

import com.kloudtek.kryptotek.CryptoAlgorithm;
import com.kloudtek.kryptotek.key.AbstractKey;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by yannick on 20/12/2014.
 */
public abstract class AbstractJCEKey<K> extends AbstractKey implements JCEKey {
    private static final Logger logger = Logger.getLogger(AbstractJCEKey.class.getName());
    protected K key;

    public AbstractJCEKey(K key, Type type, CryptoAlgorithm algorithm, boolean encryptionKey, boolean decryptionKey, boolean signingKey, boolean signatureVerificationKey) {
        super(type, algorithm, encryptionKey, decryptionKey, signingKey, signatureVerificationKey);
        this.key = key;
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
}
