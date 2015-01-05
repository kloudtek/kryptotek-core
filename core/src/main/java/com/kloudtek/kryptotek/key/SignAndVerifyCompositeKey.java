/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.key;

import com.kloudtek.kryptotek.CryptoAlgorithm;
import com.kloudtek.kryptotek.CryptoEngine;
import com.kloudtek.kryptotek.EncodedKey;
import com.kloudtek.kryptotek.InvalidKeyEncodingException;
import com.kloudtek.ktserializer.AbstractCustomSerializable;
import com.kloudtek.ktserializer.InvalidSerializedDataException;
import com.kloudtek.ktserializer.SerializationContext;
import com.kloudtek.ktserializer.Serializer;
import com.kloudtek.util.UnexpectedException;
import com.kloudtek.util.io.ByteArrayDataInputStream;
import com.kloudtek.util.io.ByteArrayDataOutputStream;
import com.kloudtek.util.io.DataInputStream;
import com.kloudtek.util.io.DataOutputStream;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class SignAndVerifyCompositeKey implements SignAndVerifyKey {
    private final CryptoEngine cryptoEngine;
    private SigningKey signingKey;
    private SignatureVerificationKey signatureVerificationKey;

    public SignAndVerifyCompositeKey(CryptoEngine cryptoEngine, SigningKey signingKey, SignatureVerificationKey signatureVerificationKey) {
        this.cryptoEngine = cryptoEngine;
        this.signingKey = signingKey;
        this.signatureVerificationKey = signatureVerificationKey;
    }

    public SigningKey getSigningKey() {
        return signingKey;
    }

    public SignatureVerificationKey getSignatureVerificationKey() {
        return signatureVerificationKey;
    }

    @Override
    public EncodedKey getEncoded() {
        return null;
    }

    @Override
    public EncodedKey getEncoded(EncodedKey.Format format) throws InvalidKeyEncodingException {
        throw new InvalidKeyEncodingException(format);
    }

    @Override
    public CryptoEngine getCryptoEngine() {
        return cryptoEngine;
    }

    @Override
    public void destroy() {
        signingKey.destroy();
        signatureVerificationKey.destroy();
    }
}
