/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.jce;

import com.kloudtek.kryptotek.CryptoEngine;
import com.kloudtek.kryptotek.EncodedKey;
import com.kloudtek.kryptotek.InvalidKeyEncodingException;
import com.kloudtek.kryptotek.key.Certificate;
import com.kloudtek.kryptotek.key.KeyType;
import com.kloudtek.kryptotek.key.PublicKey;
import com.kloudtek.kryptotek.key.SubjectKeyIdentifier;
import com.kloudtek.ktserializer.*;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.security.InvalidKeyException;

public class JCECertificate extends AbstractCustomSerializable implements Certificate {
    protected CryptoEngine cryptoEngine;
    protected String subject;
    protected SubjectKeyIdentifier subjectKeyIdentifier;
    protected PublicKey publicKey;

    public JCECertificate() {
    }

    public JCECertificate(@NotNull CryptoEngine cryptoEngine, @NotNull String subject, @NotNull SubjectKeyIdentifier subjectKeyIdentifier, @NotNull PublicKey publicKey) {
        this.cryptoEngine = cryptoEngine;
        this.subject = subject;
        this.subjectKeyIdentifier = subjectKeyIdentifier;
        this.publicKey = publicKey;
    }

    public JCECertificate(@NotNull CryptoEngine cryptoEngine, @NotNull String subject, @NotNull PublicKey publicKey) {
        this(cryptoEngine, subject, new SubjectKeyIdentifier(cryptoEngine.sha1(publicKey.getEncoded().getEncodedKey())), publicKey);
    }

    public JCECertificate(JCECryptoEngine cryptoEngine, byte[] keyData) throws InvalidSerializedDataException {
        this.cryptoEngine = cryptoEngine;
        getSerializer().deserialize(this, keyData);
    }

    public Serializer getSerializer() {
        return ((JCECryptoEngine) cryptoEngine).serializer;
    }

    @Override
    public KeyType getType() {
        return KeyType.CERTIFICATE;
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
        cryptoEngine = is.getSerializer().getInject(CryptoEngine.class);
        subject = is.readUTF();
        subjectKeyIdentifier = new SubjectKeyIdentifier(is.readData());
        is.readByte(); // key type (only RSA at the moment)
        byte[] keyData = is.readData();
        try {
            publicKey = cryptoEngine.readRSAPublicKey(keyData);
        } catch (InvalidKeyException e) {
            throw new InvalidSerializedDataException(e);
        }
    }

    @Override
    public EncodedKey getEncoded() {
        return new EncodedKey(getSerializer().serialize(this), EncodedKey.Format.SERIALIZED);
    }

    @Override
    public EncodedKey getEncoded(EncodedKey.Format format) throws InvalidKeyEncodingException {
        EncodedKey.checkSupportedFormat(format, EncodedKey.Format.SERIALIZED);
        return getEncoded();
    }

    @Override
    public byte[] serialize() {
        return getSerializer().serialize(this);
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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        JCECertificate that = (JCECertificate) o;

        if (publicKey != null ? !publicKey.equals(that.publicKey) : that.publicKey != null) return false;
        if (subject != null ? !subject.equals(that.subject) : that.subject != null) return false;
        return !(subjectKeyIdentifier != null ? !subjectKeyIdentifier.equals(that.subjectKeyIdentifier) : that.subjectKeyIdentifier != null);

    }

    @Override
    public int hashCode() {
        int result = subject != null ? subject.hashCode() : 0;
        result = 31 * result + (subjectKeyIdentifier != null ? subjectKeyIdentifier.hashCode() : 0);
        result = 31 * result + (publicKey != null ? publicKey.hashCode() : 0);
        return result;
    }
}
