/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek;

/**
 * Created by yannick on 15/09/2014.
 */

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;

public class DigestOutputStream extends FilterOutputStream {
    private boolean on = true;

    /**
     * The message digest associated with this stream.
     */
    protected Digest digest;

    /**
     * Creates a digest output stream, using the specified output stream
     * and message digest.
     *
     * @param stream the output stream.
     *
     * @param digest the message digest to associate with this stream.
     */
    public DigestOutputStream(OutputStream stream, Digest digest) {
        super(stream);
        setMessageDigest(digest);
    }

    /**
     * Returns the message digest associated with this stream.
     *
     * @return the message digest associated with this stream.
     * @see #setMessageDigest(Digest)
     */
    public Digest getDigest() {
        return digest;
    }

    /**
     * Associates the specified message digest with this stream.
     *
     * @param digest the message digest to be associated with this stream.
     * @see #getDigest()
     */
    public void setMessageDigest(Digest digest) {
        this.digest = digest;
    }

    /**
     * Updates the message digest (if the digest function is on) using
     * the specified byte, and in any case writes the byte
     * to the output stream. That is, if the digest function is on
     * (see {@link #on(boolean) on}), this method calls
     * {@code update} on the message digest associated with this
     * stream, passing it the byte {@code b}. This method then
     * writes the byte to the output stream, blocking until the byte
     * is actually written.
     *
     * @param b the byte to be used for updating and writing to the
     * output stream.
     *
     * @exception java.io.IOException if an I/O error occurs.
     *
     * @see MessageDigest#update(byte)
     */
    public void write(int b) throws IOException {
        out.write(b);
        if (on) {
            digest.update((byte)b);
        }
    }

    /**
     * Updates the message digest (if the digest function is on) using
     * the specified subarray, and in any case writes the subarray to
     * the output stream. That is, if the digest function is on (see
     * {@link #on(boolean) on}), this method calls {@code update}
     * on the message digest associated with this stream, passing it
     * the subarray specifications. This method then writes the subarray
     * bytes to the output stream, blocking until the bytes are actually
     * written.
     *
     * @param b the array containing the subarray to be used for updating
     * and writing to the output stream.
     *
     * @param off the offset into {@code b} of the first byte to
     * be updated and written.
     *
     * @param len the number of bytes of data to be updated and written
     * from {@code b}, starting at offset {@code off}.
     *
     * @exception IOException if an I/O error occurs.
     *
     * @see MessageDigest#update(byte[], int, int)
     */
    public void write(byte[] b, int off, int len) throws IOException {
        out.write(b, off, len);
        if (on) {
            digest.update(b, off, len);
        }
    }

    /**
     * Turns the digest function on or off. The default is on.  When
     * it is on, a call to one of the {@code write} methods results in an
     * update on the message digest.  But when it is off, the message
     * digest is not updated.
     *
     * @param on true to turn the digest function on, false to turn it
     * off.
     */
    public void on(boolean on) {
        this.on = on;
    }

    /**
     * Prints a string representation of this digest output stream and
     * its associated message digest object.
     */
    public String toString() {
        return "[Digest Output Stream] " + digest.toString();
    }
}
