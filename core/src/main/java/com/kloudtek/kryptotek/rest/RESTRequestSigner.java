/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.rest;

import com.kloudtek.util.StringUtils;
import com.kloudtek.util.TimeUtils;
import com.kloudtek.util.validation.ValidationUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Date;
import java.util.UUID;

import static com.kloudtek.util.StringUtils.utf8;

/**
 * Created by yannick on 28/10/2014.
 */
public class RESTRequestSigner {
    private String method;
    private String uri;
    private String nounce;
    private String timestamp;
    private String identity;
    private byte[] content;

    public RESTRequestSigner(String method, String uri, String nounce, String timestamp, String identity) {
        this.method = method;
        this.uri = uri;
        this.nounce = nounce;
        this.timestamp = timestamp;
        this.identity = identity;
    }

    public RESTRequestSigner(String method, String uri, long timeDifferential, String identity) {
        this(method, uri, UUID.randomUUID().toString(), TimeUtils.formatISOUTCDateTime(new Date(System.currentTimeMillis() - timeDifferential)), identity );
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getUri() {
        return uri;
    }

    public void setUri(String uri) {
        this.uri = uri;
    }

    public String getNounce() {
        return nounce;
    }

    public void setNounce(String nounce) {
        this.nounce = nounce;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }

    public String getIdentity() {
        return identity;
    }

    public void setIdentity(String identity) {
        this.identity = identity;
    }

    public byte[] getContent() {
        return content;
    }

    public void setContent(byte[] content) {
        this.content = content;
    }

    public byte[] getDataToSign() throws IOException {
        if( ! ValidationUtils.notEmpty(method,uri,nounce,timestamp,identity)) {
            throw new IllegalArgumentException("Not all signing parameters have been set");
        }
        String dataToSign = new StringBuilder(method.toUpperCase().trim()).append('\n').append(uri.trim()).append('\n')
                .append(nounce).append('\n').append(timestamp.trim().toUpperCase()).append('\n').append(identity).toString();
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        buf.write(StringUtils.utf8(dataToSign));
        if( content != null ) {
            buf.write(content);
        }
        buf.close();
        return buf.toByteArray();
    }
}
