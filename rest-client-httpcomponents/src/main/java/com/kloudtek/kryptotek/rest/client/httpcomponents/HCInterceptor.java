/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.rest.client.httpcomponents;

import com.kloudtek.util.StringUtils;
import com.kloudtek.util.TimeUtils;
import com.kloudtek.util.io.BoundedOutputStream;
import org.apache.http.*;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.protocol.HttpContext;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.Date;
import java.util.UUID;
import java.util.logging.Logger;

import static com.kloudtek.util.StringUtils.utf8;

/**
 * Created by yannick on 23/10/2014.
 */
public abstract class HCInterceptor implements HttpRequestInterceptor, HttpResponseInterceptor {
    private static final Logger logger = Logger.getLogger(HCInterceptor.class.getName());
    public static final String KRYPTOTEK_REST_SIGNTOKEN = "kryptotek.rest.signtoken";
    public static final String AUTHORIZATION = "AUTHORIZATION";
    public static final String REQUEST_AUTHZ = "request_authz";
    private String identity;
    private TimeSync timeSync;
    private Long timeDifferential;
    private Long responseSizeLimit;

    protected HCInterceptor(String identity, TimeSync timeSync, Long responseSizeLimit) {
        this.identity = identity;
        this.timeSync = timeSync;
    }

    @Override
    public void process(HttpRequest request, HttpContext context) throws HttpException, IOException {
        if( timeSync != null && timeDifferential == null ) {
            // yes this is not synchronized, there's no harm in worse case scenario (worse can happen is syncing happening another time or two)
            timeDifferential = timeSync.getTimeDifferential(request, context);
        }
        RequestLine requestLine = request.getRequestLine();
        String nounce = UUID.randomUUID().toString();
        long timestamp = timeDifferential != null ? System.currentTimeMillis() - timeDifferential : System.currentTimeMillis();
        String timestampStr = TimeUtils.formatISOUTCDateTime(new Date(timestamp));
        request.addHeader("X-NOUNCE", nounce);
        request.addHeader("X-TIMESTAMP", timestampStr);
        request.addHeader("X-IDENTITY", identity);
        ByteArrayOutputStream buf = buildSigningData(requestLine.getMethod().toUpperCase().trim(), requestLine.getUri(), nounce, timestampStr, identity);
        // TODO sign content-length and type
        HttpEntity entity = loadEntity(request);
        if( entity != null ) {
            entity.writeTo(buf);
        }
        // generate and add signature
        buf.close();
        try {
            String signature = sign(buf.toByteArray());
            context.setAttribute(REQUEST_AUTHZ,signature);
            request.addHeader(AUTHORIZATION, signature);
        } catch (Exception e) {
            throw new HttpException(e.getMessage(),e);
        }
    }

    @Override
    public void process(HttpResponse response, HttpContext context) throws HttpException, IOException {
        Header[] signatures = response.getHeaders("SIGNATURE");
        if( signatures == null || signatures.length != 1 ) {
            throw new HttpException("response is missing (or has more than one) SIGNATURE header");
        }
        ByteArrayOutputStream signingData = buildSigningData((String) context.getAttribute(REQUEST_AUTHZ), Integer.toString(response.getStatusLine().getStatusCode()));
        loadEntity(response, responseSizeLimit).writeTo(signingData);
        try {
            verifySignature(signatures[0].getValue(),signingData.toByteArray());
        } catch (InvalidKeyException e) {
            throw new HttpException(e.getMessage(),e);
        } catch (SignatureException e) {
            throw new HttpException("Invalid response signature");
        }
    }

    protected abstract String sign(byte[] data) throws InvalidKeyException, SignatureException;

    protected abstract void verifySignature(String signature, byte[] signedData) throws InvalidKeyException, SignatureException;

    public HttpClientBuilder add(HttpClientBuilder builder) {
        return builder.addInterceptorLast((HttpRequestInterceptor)this).addInterceptorFirst((HttpResponseInterceptor) this);
    }

    public HttpClientBuilder createClientBuilder() {
        return add(HttpClientBuilder.create());
    }

    public CloseableHttpClient createClient() {
        return createClientBuilder().build();
    }

    private HttpEntity loadEntity(HttpRequest request) throws IOException {
        if( request instanceof HttpEntityEnclosingRequest ) {
            HttpEntity originalEntity = ((HttpEntityEnclosingRequest) request).getEntity();
            if( originalEntity != null ) {
                HttpEntity loadedEntity = loadEntity(originalEntity, null);
                ((HttpEntityEnclosingRequest) request).setEntity(loadedEntity);
                return loadedEntity;
            }
        }
        return null;
    }

    private HttpEntity loadEntity(HttpResponse response, Long responseSizeLimit) throws IOException {
        HttpEntity entity = loadEntity(response.getEntity(), responseSizeLimit);
        response.setEntity(entity);
        return entity;
    }

    private static HttpEntity loadEntity(HttpEntity entity, Long limit ) throws IOException {
        if( entity.isRepeatable() ) {
            return entity;
        } else {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            if( limit != null ) {
                entity.writeTo(new BoundedOutputStream(buffer,limit,true));
            } else {
                entity.writeTo(buffer);
            }
            buffer.close();
            ByteArrayEntity byteArrayEntity = new ByteArrayEntity(buffer.toByteArray());
            return byteArrayEntity;
        }
    }

    private static ByteArrayOutputStream buildSigningData(String... data) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        for (String d : data) {
            if( d != null ) {
                buffer.write(utf8(d.trim()));
            }
            buffer.write(0);
        }
        return buffer;
    }
}
