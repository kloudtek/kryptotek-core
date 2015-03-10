/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.rest;

import com.kloudtek.util.StringUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Created by yannick on 28/10/2014.
 */
public class RESTResponseSigner {
    private String nounce;
    private String requestSignature;
    private int statusCode;
    private byte[] content;

    public RESTResponseSigner() {
    }

    public RESTResponseSigner(String nounce, String requestSignature, int statusCode) {
        this.nounce = nounce;
        this.requestSignature = requestSignature;
        this.statusCode = statusCode;
    }

    public RESTResponseSigner(String nounce, String requestSignature, int statusCode, byte[] content) {
        this.nounce = nounce;
        this.requestSignature = requestSignature;
        this.statusCode = statusCode;
        this.content = content;
    }

    public String getNounce() {
        return nounce;
    }

    public void setNounce(String nounce) {
        this.nounce = nounce;
    }

    public String getRequestSignature() {
        return requestSignature;
    }

    public void setRequestSignature(String requestSignature) {
        this.requestSignature = requestSignature;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }

    public byte[] getContent() {
        return content;
    }

    public void setContent(byte[] content) {
        this.content = content;
    }

    public byte[] getDataToSign() throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        buf.write(StringUtils.utf8(nounce.trim()+"\n"+requestSignature.trim()+"\n"+Integer.toString(statusCode)+"\n"));
        if( content != null ) {
            buf.write(content);
        }
        buf.close();
        return buf.toByteArray();
    }
}
