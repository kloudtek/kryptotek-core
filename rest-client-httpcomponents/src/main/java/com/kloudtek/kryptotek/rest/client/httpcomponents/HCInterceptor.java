/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.rest.client.httpcomponents;

import com.kloudtek.util.TimeUtils;
import org.apache.http.*;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.protocol.HttpContext;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
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
    private String identity;
    private TimeSync timeSync;
    private Long timeDifferential;

    protected HCInterceptor(String identity, TimeSync timeSync) {
        this.identity = identity;
        this.timeSync = timeSync;
    }

    @Override
    public void process(HttpRequest request, HttpContext context) throws HttpException, IOException {
        if( timeSync != null && timeDifferential == null ) {
            // yes this is not synchronized, there's no harm in worse case scenario (worse can happen is syncing happening another time or two)
            timeDifferential = timeSync.getTimeDifferential(request, context);
        }
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        // add method
        RequestLine requestLine = request.getRequestLine();
        buf.write(utf8(requestLine.getMethod().toUpperCase().trim()));
        buf.write(0);
        // add path (with parameters)
        buf.write(utf8(requestLine.getUri().trim()));
        buf.write(0);
        // Generate and add nounce
        String nounce = UUID.randomUUID().toString();
        buf.write(utf8(nounce));
        request.addHeader("X-NOUNCE", nounce);
        buf.write(0);
        // Generate and add time stamp
        // TODO add time sync
        long timestamp = timeDifferential != null ? System.currentTimeMillis() - timeDifferential : System.currentTimeMillis();
        String timestampStr = TimeUtils.formatISOUTCDateTime(new Date(timestamp));
        buf.write(utf8(timestampStr));
        request.addHeader("X-TIMESTAMP", timestampStr);
        buf.write(0);
        // add identity
        buf.write(utf8(identity));
        request.addHeader("X-IDENTITY", identity);
        buf.write(0);
        // add content
        if (request instanceof HttpEntityEnclosingRequest) {
            HttpEntity entity = ((HttpEntityEnclosingRequest) request).getEntity();
            if (!entity.isRepeatable()) {
                throw new HttpException("Only repeatable entities can be signed");
            }
            entity.writeTo(buf);
        }
        // generate and add signature
        buf.close();
        try {
            request.addHeader("AUTHORIZATION",sign(buf.toByteArray()));
        } catch (InvalidKeyException e) {
            throw new HttpException(e.getMessage(),e);
        }
    }

    protected abstract String sign(byte[] data) throws InvalidKeyException;

    @Override
    public void process(HttpResponse response, HttpContext context) throws HttpException, IOException {
    }

    public HttpClientBuilder add(HttpClientBuilder builder) {
        return builder.addInterceptorLast((HttpRequestInterceptor)this).addInterceptorFirst((HttpResponseInterceptor) this);
    }

    public HttpClientBuilder createClientBuilder() {
        return add(HttpClientBuilder.create());
    }
}
