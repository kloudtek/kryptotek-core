/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.jce;

import com.kloudtek.kryptotek.CryptoEngine;
import com.kloudtek.kryptotek.key.AbstractSimpleCertificate;
import com.kloudtek.kryptotek.key.PublicKey;
import com.kloudtek.kryptotek.key.SubjectKeyIdentifier;
import com.kloudtek.ktserializer.ClassMapper;
import com.kloudtek.ktserializer.InvalidSerializedDataException;
import org.jetbrains.annotations.NotNull;

public class JCESimpleCertificate extends AbstractSimpleCertificate {
    public JCESimpleCertificate() {
    }

    public JCESimpleCertificate(@NotNull CryptoEngine cryptoEngine, @NotNull String subject, @NotNull SubjectKeyIdentifier subjectKeyIdentifier, @NotNull PublicKey publicKey) {
        super(cryptoEngine, subject, subjectKeyIdentifier, publicKey);
    }

    public JCESimpleCertificate(@NotNull CryptoEngine cryptoEngine, @NotNull String subject, @NotNull PublicKey publicKey) {
        super(cryptoEngine, subject, publicKey);
    }

    public JCESimpleCertificate(JCECryptoEngine cryptoEngine, byte[] keyData) throws InvalidSerializedDataException {
        super(cryptoEngine, keyData);
    }

    @Override
    public ClassMapper getClassMapper() {
        return JCECryptoEngine.classMapper;
    }
}
