/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.rest.server.jaxrs;

import com.kloudtek.kryptotek.CryptoEngine;
import com.kloudtek.kryptotek.CryptoUtils;
import com.kloudtek.kryptotek.DigestAlgorithm;
import com.kloudtek.kryptotek.key.SignatureVerificationKey;
import com.kloudtek.kryptotek.key.SigningKey;
import com.kloudtek.kryptotek.rest.RESTRequestSigner;
import com.kloudtek.kryptotek.rest.RESTResponseSigner;
import com.kloudtek.kryptotek.rest.ReplayAttackValidator;
import com.kloudtek.kryptotek.rest.ReplayAttackValidatorNoOpImpl;
import com.kloudtek.util.BackendAccessException;
import com.kloudtek.util.StringUtils;
import com.kloudtek.util.TimeUtils;
import com.kloudtek.util.io.BoundedOutputStream;
import com.kloudtek.util.io.IOUtils;
import com.kloudtek.util.validation.ValidationUtils;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;
import javax.ws.rs.ext.WriterInterceptor;
import javax.ws.rs.ext.WriterInterceptorContext;
import java.io.*;
import java.net.URI;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.text.ParseException;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

import static com.kloudtek.kryptotek.DigestAlgorithm.SHA256;
import static com.kloudtek.kryptotek.rest.RESTRequestSigner.*;
import static javax.ws.rs.core.Response.Status.*;

/**
 * Created by yannick on 28/10/2014.
 */
public abstract class RESTAuthenticationFilter implements ContainerRequestFilter, ContainerResponseFilter, WriterInterceptor {
    private static final Logger logger = Logger.getLogger(RESTAuthenticationFilter.class.getName());
    public static final String TMP_REQDETAILS = "X-TMP-REQDETAILS";
    public static final long DEFAULT_EXPIRY = 300000L;
    protected Long contentMaxSize;
    protected DigestAlgorithm digestAlgorithm;
    protected long expiry = DEFAULT_EXPIRY;
    protected ReplayAttackValidator replayAttackValidator;
    protected CryptoEngine cryptoEngine;

    public RESTAuthenticationFilter() {
        this(CryptoUtils.getEngine());
    }

    public RESTAuthenticationFilter(CryptoEngine cryptoEngine) {
        this(cryptoEngine, new ReplayAttackValidatorNoOpImpl());
    }

    public RESTAuthenticationFilter(CryptoEngine cryptoEngine, ReplayAttackValidator replayAttackValidator) {
        this(cryptoEngine, null, SHA256, DEFAULT_EXPIRY, replayAttackValidator);
    }

    public RESTAuthenticationFilter(CryptoEngine cryptoEngine, Long contentMaxSize, DigestAlgorithm digestAlgorithm,
                                    long expiry, ReplayAttackValidator replayAttackValidator) {
        this.cryptoEngine = cryptoEngine;
        this.contentMaxSize = contentMaxSize;
        this.digestAlgorithm = digestAlgorithm;
        this.expiry = expiry;
        this.replayAttackValidator = replayAttackValidator;
    }

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        String nounce = requestContext.getHeaderString(HEADER_NOUNCE);
        String identity = requestContext.getHeaderString(HEADER_IDENTITY);
        String timestampStr = requestContext.getHeaderString(HEADER_TIMESTAMP);
        String signature = requestContext.getHeaderString(HEADER_SIGNATURE);
        if (!ValidationUtils.notEmpty(nounce, identity, timestampStr, signature)) {
            logger.warning("Unauthorized request (missing any of nounce, identify, timestamp, signature)");
            throw new AccessUnauthorizedException();
        }
        URI requestUri = requestContext.getUriInfo().getRequestUri();
        StringBuilder path = new StringBuilder(requestUri.getPath());
        if (requestUri.getRawQuery() != null) {
            path.append('?').append(requestUri.getRawQuery());
        }
        RESTRequestSigner restRequestSigner = new RESTRequestSigner(requestContext.getMethod(), path.toString(), nounce, timestampStr, identity);
        ByteArrayOutputStream content = new ByteArrayOutputStream();
        InputStream is = requestContext.getEntityStream();
        IOUtils.copy(is, contentMaxSize != null ? new BoundedOutputStream(content, contentMaxSize, true) : content);
        byte[] contentData = content.toByteArray();
        restRequestSigner.setContent(contentData);
        try {
            Date timestamp = TimeUtils.parseISOUTCDateTime(timestampStr);
            if (timestamp.after(new Date(System.currentTimeMillis() + expiry))) {
                logger.warning("Unauthorized request (expired timestamp): " + timestampStr);
                throw new AccessUnauthorizedException();
            }
            if (replayAttackValidator.checkNounceReplay(nounce)) {
                logger.warning("Unauthorized request (duplicated nounce): " + nounce);
                throw new AccessUnauthorizedException();
            }
            requestContext.setEntityStream(new ByteArrayInputStream(contentData));
            if (!verifySignature(identity, restRequestSigner.getDataToSign(), signature)) {
                logger.warning("Unauthorized request (invalid signature): " + restRequestSigner.toString());
                throw new AccessUnauthorizedException();
            }
        } catch (ParseException e) {
            throw new WebApplicationException(BAD_REQUEST);
        }
    }

    @Override
    public void aroundWriteTo(WriterInterceptorContext responseCtx) throws IOException, WebApplicationException {
        ByteArrayOutputStream content = new ByteArrayOutputStream();
        OutputStream oldStream = responseCtx.getOutputStream();
        responseCtx.setOutputStream(content);
        responseCtx.proceed();
        RequestDetails requestDetails = (RequestDetails) responseCtx.getProperty(TMP_REQDETAILS);
        byte[] contentData = content.toByteArray();
        RESTResponseSigner responseSigner = new RESTResponseSigner(requestDetails.nounce, requestDetails.signature, requestDetails.statusCode, contentData);
        try {
            responseCtx.getHeaders().add(RESTRequestSigner.HEADER_SIGNATURE, signResponse(requestDetails.identity, responseSigner.getDataToSign()));
        } catch (InvalidKeyException e) {
            logger.log(Level.SEVERE, "Invalid key for identity " + requestDetails.identity + " : " + e.getMessage(), e);
            throw new AccessUnauthorizedException();
        } catch (BackendAccessException e) {
            logger.log(Level.SEVERE, e.getMessage(), e);
            throw new WebApplicationException(INTERNAL_SERVER_ERROR);
        }
        oldStream.write(contentData);
    }

    @Override
    public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) throws IOException {
        RequestDetails requestDetails = new RequestDetails(requestContext.getHeaderString(HEADER_NOUNCE),
                requestContext.getHeaderString(HEADER_SIGNATURE), requestContext.getHeaderString(HEADER_IDENTITY), responseContext.getStatus());
        responseContext.getHeaders().add(HEADER_TIMESTAMP, requestDetails.responseTimestamp);
        requestContext.setProperty(TMP_REQDETAILS, requestDetails);
    }

    private boolean verifySignature(String identity, byte[] dataToSign, String signature) {
        try {
            SignatureVerificationKey key = findVerificationKey(identity);
            if (key == null) {
                return false;
            }
            try {
                cryptoEngine.verifySignature(key, digestAlgorithm, dataToSign, StringUtils.base64Decode(signature));
                return true;
            } catch (InvalidKeyException e) {
                logger.log(Level.SEVERE, "Invalid key found while verifying signature: " + e.getMessage(), e);
                throw new WebApplicationException(INTERNAL_SERVER_ERROR);
            } catch (SignatureException e) {
                return false;
            }
        } catch (BackendAccessException e) {
            logger.log(Level.SEVERE, e.getMessage(), e);
            throw new WebApplicationException(INTERNAL_SERVER_ERROR);
        }
    }

    private String signResponse(String identity, byte[] data) throws InvalidKeyException, BackendAccessException {
        SigningKey key = findSigningKey(identity);
        if (key == null) {
            logger.severe("Unable to find key for response signing: " + identity);
            throw new WebApplicationException(UNAUTHORIZED);
        }
        return StringUtils.base64Encode(cryptoEngine.sign(key, digestAlgorithm, data));
    }

    protected abstract SignatureVerificationKey findVerificationKey(String identity) throws BackendAccessException;

    protected abstract SigningKey findSigningKey(String identity) throws BackendAccessException;

    public class RequestDetails {
        private String nounce;
        private String signature;
        private String identity;
        private String responseTimestamp;
        private int statusCode;

        public RequestDetails(String nounce, String signature, String identity, int statusCode) {
            this.nounce = nounce;
            this.signature = signature;
            this.identity = identity;
            this.statusCode = statusCode;
            responseTimestamp = TimeUtils.formatISOUTCDateTime(new Date());
        }
    }
}
