/*
 * Copyright (c) 2016 Kloudtek Ltd
 */

package com.kloudtek.kryptotek;

import com.kloudtek.kryptotek.jce.*;
import com.kloudtek.ktserializer.Library;
import org.jetbrains.annotations.NotNull;

/**
 * Created by yannick on 1/25/16.
 */
public class KryptoSerLib implements Library {
    public static final Class[] SERIALIZABLE_CLASSES = new Class[]{JCEAESKey.class, JCEHMACSHA1Key.class,
            JCEHMACSHA256Key.class, JCEHMACSHA512Key.class, JCERSAPrivateKey.class, JCERSAPublicKey.class, JCERSAKeyPair.class,
            JCECertificate.class, JCEDHKeyPair.class, JCEDHPrivateKey.class, JCEDHPublicKey.class};

    @NotNull
    @Override
    public Class<?>[] getClasses() {
        return SERIALIZABLE_CLASSES;
    }
}
