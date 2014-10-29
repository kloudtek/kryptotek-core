/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.rest.client.httpcomponents;

import com.kloudtek.kryptotek.rest.RESTRequestSigner;
import com.kloudtek.kryptotek.rest.RESTResponseSigner;
import com.kloudtek.util.io.BoundedOutputStream;
import org.apache.http.*;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.protocol.HttpContext;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.logging.Logger;

import static com.kloudtek.kryptotek.rest.RESTRequestSigner.*;
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
        this.responseSizeLimit = responseSizeLimit;
    }

    @Override
    public void process(HttpRequest request, HttpContext context) throws HttpException, IOException {
        if( timeSync != null && timeDifferential == null ) {
            // yes this is not synchronized, there's no harm in worse case scenario (worse can happen is syncing happening another time or two)
            timeDifferential = timeSync.getTimeDifferential(request, context);
        }
        RequestLine requestLine = request.getRequestLine();
        RESTRequestSigner requestSigner = new RESTRequestSigner(request.getRequestLine().getMethod(), requestLine.getUri(), timeDifferential != null ? timeDifferential : 0, identity);
        request.addHeader(HEADER_NOUNCE, requestSigner.getNounce());
        request.addHeader(HEADER_TIMESTAMP, requestSigner.getTimestamp());
        request.addHeader(HEADER_IDENTITY, identity);
        // TODO sign content-length and type
        byte[] content = getContent(request);
        if( content != null ) {
            requestSigner.setContent(content);
        }
        try {
            String signature = sign(requestSigner.getDataToSign());
            context.setAttribute(REQUEST_AUTHZ,signature);
            request.addHeader(HEADER_SIGNATURE, signature);
        } catch (Exception e) {
            throw new HttpException(e.getMessage(),e);
        }
    }

    @Override
    public void process(HttpResponse response, HttpContext context) throws HttpException, IOException {
        Header[] signatures = response.getHeaders(HEADER_SIGNATURE);
        if( signatures == null || signatures.length != 1 ) {
            throw new HttpException("response is missing (or has more than one) "+HEADER_SIGNATURE+" header");
        }
        RESTResponseSigner responseSigner = new RESTResponseSigner((String) context.getAttribute(REQUEST_AUTHZ), response.getStatusLine().getStatusCode());
        HttpEntity entity = loadEntity(response, responseSizeLimit);
        byte[] content = getContent(entity);
        if( content != null ) {
            responseSigner.setContent(content);
        }
        try {
            verifySignature(signatures[0].getValue(),responseSigner.getDataToSign());
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

    public String getIdentity() {
        return identity;
    }

    public void setIdentity(String identity) {
        this.identity = identity;
    }

    public TimeSync getTimeSync() {
        return timeSync;
    }

    public void setTimeSync(TimeSync timeSync) {
        this.timeSync = timeSync;
    }

    public Long getTimeDifferential() {
        return timeDifferential;
    }

    public void setTimeDifferential(Long timeDifferential) {
        this.timeDifferential = timeDifferential;
    }

    public Long getResponseSizeLimit() {
        return responseSizeLimit;
    }

    public void setResponseSizeLimit(Long responseSizeLimit) {
        this.responseSizeLimit = responseSizeLimit;
    }

    private static byte[] getContent(HttpRequest request) throws IOException {
        return getContent(loadEntity(request));
    }

    private static byte[] getContent(HttpEntity entity) throws IOException {
        if( entity != null ) {
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            entity.writeTo(buf);
            buf.close();
            return buf.toByteArray();
        } else {
            return null;
        }
    }

    private static HttpEntity loadEntity(HttpRequest request) throws IOException {
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
            return new ByteArrayEntity(buffer.toByteArray());
        }
    }
}
