/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.rest;

import com.kloudtek.util.StringUtils;
import com.kloudtek.util.validation.ValidationUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Created by yannick on 28/10/2014.
 */
public class RESTResponseSigner {
    private String authorization;
    private int statusCode;
    private byte[] content;

    public RESTResponseSigner() {
    }

    public RESTResponseSigner(String authorization, int statusCode) {
        this.authorization = authorization;
        this.statusCode = statusCode;
    }

    public RESTResponseSigner(String authorization, int statusCode, byte[] content) {
        this.authorization = authorization;
        this.statusCode = statusCode;
        this.content = content;
    }

    public String getAuthorization() {
        return authorization;
    }

    public void setAuthorization(String authorization) {
        this.authorization = authorization;
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
        buf.write(StringUtils.utf8(authorization.trim()+"\n"+Integer.toString(statusCode)+"\n"));
        if( content != null ) {
            buf.write(content);
        }
        buf.close();
        return buf.toByteArray();
    }
}
