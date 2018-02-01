/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.key;

import com.kloudtek.ktserializer.AbstractCustomSerializable;
import com.kloudtek.ktserializer.DeserializationStream;
import com.kloudtek.ktserializer.InvalidSerializedDataException;
import com.kloudtek.ktserializer.SerializationStream;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.Arrays;

/**
 * Created by yannick on 03/01/2015.
 */
public class SubjectKeyIdentifier extends AbstractCustomSerializable {
    private byte[] keyIdentifier;

    public SubjectKeyIdentifier() {
    }

    public SubjectKeyIdentifier(@NotNull byte[] keyIdentifier) {
        this.keyIdentifier = keyIdentifier;
    }

    public byte[] getKeyIdentifier() {
        return keyIdentifier;
    }

    @Override
    public int getSerializationVersion() {
        return 0;
    }

    @Override
    public void serialize(@NotNull SerializationStream os) throws IOException {
        os.writeData(keyIdentifier);
    }

    @Override
    public void deserialize(@NotNull DeserializationStream is, int version) throws IOException, InvalidSerializedDataException {
        keyIdentifier = is.readData();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        SubjectKeyIdentifier that = (SubjectKeyIdentifier) o;

        return Arrays.equals(keyIdentifier, that.keyIdentifier);

    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(keyIdentifier);
    }
}
