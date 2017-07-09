/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.key;

import com.kloudtek.ktserializer.AbstractCustomSerializable;
import com.kloudtek.ktserializer.DeserializationStream;
import com.kloudtek.ktserializer.InvalidSerializedDataException;
import com.kloudtek.ktserializer.SerializationStream;
import com.kloudtek.util.StringUtils;
import com.kloudtek.util.UnexpectedException;
import com.kloudtek.util.io.ByteArrayDataInputStream;
import com.kloudtek.util.io.ByteArrayDataOutputStream;
import com.kloudtek.util.io.DataInputStream;
import com.kloudtek.util.io.DataOutputStream;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.math.BigInteger;

/**
 * Created by yannick on 26/01/2015.
 */
public class DHParameters extends AbstractCustomSerializable {
    private BigInteger p;
    private BigInteger g;
    private int l;

    public DHParameters(BigInteger p, BigInteger g) {
        this.p = p;
        this.g = g;
        this.l = 0;
    }

    public DHParameters(BigInteger p, BigInteger g, int l) {
        this.p = p;
        this.g = g;
        this.l = l;
    }

    public DHParameters(String base64Encoded) {
        this(StringUtils.base64Decode(base64Encoded));
    }

    public DHParameters(byte[] dhParamBytesArray) {
        try {
            readByteArray(new ByteArrayDataInputStream(dhParamBytesArray));
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public DHParameters(DataInputStream is) throws IOException {
        readByteArray(is);
    }

    public BigInteger getP() {
        return this.p;
    }

    public BigInteger getG() {
        return this.g;
    }

    public int getL() {
        return this.l;
    }

    public String toBase64Encoded() {
        return StringUtils.base64Encode(toByteArray());
    }

    public void toByteArray(DataOutputStream os) throws IOException {
        os.writeData(p.toByteArray());
        os.writeData(g.toByteArray());
        os.writeInt(l);
    }

    public byte[] toByteArray() {
        try {
            final ByteArrayDataOutputStream buf = new ByteArrayDataOutputStream();
            toByteArray(buf);
            buf.close();
            return buf.toByteArray();
        } catch (IOException e) {
            throw new UnexpectedException(e);
        }
    }

    @Override
    public void serialize(SerializationStream ss) throws IOException {
        toByteArray(ss);
    }

    @Override
    public void deserialize(@NotNull DeserializationStream deserializationStream, int i) throws IOException, InvalidSerializedDataException {
        readByteArray(deserializationStream);
    }

    private void readByteArray(DataInputStream is) throws IOException {
        p = new BigInteger(is.readData());
        g = new BigInteger(is.readData());
        l = is.readInt();
    }
}
