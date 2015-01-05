/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.key;

import com.kloudtek.kryptotek.CryptoEngine;
import com.kloudtek.kryptotek.EncodedKey;
import com.kloudtek.kryptotek.InvalidKeyEncodingException;
import com.kloudtek.ktserializer.*;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.security.InvalidKeyException;

public class SimpleCertificate extends AbstractCustomSerializable implements Certificate {
    private final CryptoEngine cryptoEngine;
    private String subject;
    private SubjectKeyIdentifier subjectKeyIdentifier;
    private PublicKey publicKey;

    public SimpleCertificate(CryptoEngine cryptoEngine) {
        this.cryptoEngine = cryptoEngine;
    }

    public SimpleCertificate(@NotNull CryptoEngine cryptoEngine, @NotNull String subject,
                             @NotNull SubjectKeyIdentifier subjectKeyIdentifier, @NotNull PublicKey publicKey) {
        this.cryptoEngine = cryptoEngine;
        this.subject = subject;
        this.subjectKeyIdentifier = subjectKeyIdentifier;
        this.publicKey = publicKey;
    }

    @Override
    public int getVersion() {
        return 0;
    }

    @Override
    public void serialize(@NotNull SerializationStream os) throws IOException {
        os.writeUTF(subject);
        os.writeData(subjectKeyIdentifier.getKeyIdentifier());
        os.writeByte(0); // key type (only RSA at the moment)
        os.writeData(publicKey.getEncoded().getEncodedKey());
    }

    @Override
    public void deserialize(@NotNull DeserializationStream is, int version) throws IOException, InvalidSerializedDataException {
        subject = is.readUTF();
        subjectKeyIdentifier = new SubjectKeyIdentifier(is.readData());
        is.readByte(); // key type
        byte[] keyData = is.readData();
        try {
            publicKey = cryptoEngine.readRSAPublicKey(keyData);
        } catch (InvalidKeyException e) {
            throw new InvalidSerializedDataException(e);
        }
    }

    @Override
    public EncodedKey getEncoded() {
        return new EncodedKey(Serializer.serialize(this), EncodedKey.Format.SERIALIZED);
    }

    @Override
    public EncodedKey getEncoded(EncodedKey.Format format) throws InvalidKeyEncodingException {
        EncodedKey.checkSupportedFormat(format, EncodedKey.Format.SERIALIZED);
        return getEncoded();
    }

    @Override
    public CryptoEngine getCryptoEngine() {
        return cryptoEngine;
    }

    @Override
    public String getSubject() {
        return subject;
    }

    @Override
    public SubjectKeyIdentifier getSubjectKeyIdentifier() {
        return subjectKeyIdentifier;
    }

    @Override
    public PublicKey getPublicKey() {
        return publicKey;
    }

    @Override
    public void destroy() {
        publicKey.destroy();
    }
}
