/*
 * Copyright (c) 2016 Kloudtek Ltd
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
import com.kloudtek.util.UnexpectedException;
import com.kloudtek.util.io.BoundedOutputStream;
import com.kloudtek.util.io.IOUtils;
import com.kloudtek.util.validation.ValidationUtils;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

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
import java.security.Principal;
import java.security.SignatureException;
import java.text.ParseException;
import java.util.Date;
import java.util.List;

import static com.kloudtek.kryptotek.CryptoUtils.fingerprint;
import static com.kloudtek.kryptotek.DigestAlgorithm.SHA256;
import static com.kloudtek.kryptotek.rest.RESTRequestSigner.*;
import static javax.ws.rs.core.Response.Status.BAD_REQUEST;
import static javax.ws.rs.core.Response.Status.INTERNAL_SERVER_ERROR;

/**
 * Created by yannick on 28/10/2014.
 */
public abstract class RESTAuthenticationFilter implements ContainerRequestFilter, ContainerResponseFilter, WriterInterceptor {
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(RESTAuthenticationFilter.class);
    public static final String TMP_REQDETAILS = "X-TMP-REQDETAILS";
    public static final long DEFAULT_EXPIRY = 300000L;
    public static final String MDC_IDENTITY = "restauth-identity";
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
        logger.debug("REST Authentication filter using crypto engine: " + cryptoEngine.getClass().getName());
    }

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        String nonce = requestContext.getHeaderString(HEADER_NONCE);
        String identity = requestContext.getHeaderString(HEADER_IDENTITY);
        try {
            if (StringUtils.isNotEmpty(identity)) {
                MDC.put(MDC_IDENTITY, identity);
            }
            String timestampStr = requestContext.getHeaderString(HEADER_TIMESTAMP);
            String signature = requestContext.getHeaderString(HEADER_SIGNATURE);
            if (!ValidationUtils.notEmpty(nonce, identity, timestampStr, signature)) {
                logUnauthorizedAccess("Unauthorized request (missing any of nonce, identify, timestamp, signature)", requestContext);
                throw new AccessUnauthorizedException();
            }
            URI requestUri = requestContext.getUriInfo().getRequestUri();
            StringBuilder path = new StringBuilder(requestUri.getPath());
            if (requestUri.getRawQuery() != null) {
                path.append('?').append(requestUri.getRawQuery());
            }
            RESTRequestSigner restRequestSigner = new RESTRequestSigner(requestContext.getMethod(), path.toString(), nonce, timestampStr, identity);
            ByteArrayOutputStream content = new ByteArrayOutputStream();
            InputStream is = requestContext.getEntityStream();
            IOUtils.copy(is, contentMaxSize != null ? new BoundedOutputStream(content, contentMaxSize, true) : content);
            byte[] contentData = content.toByteArray();
            restRequestSigner.setContent(contentData);
            try {
                Date timestamp = TimeUtils.parseISOUTCDateTime(timestampStr);
                if (timestamp.after(new Date(System.currentTimeMillis() + expiry))) {
                    String message = "Unauthorized request (expired timestamp): " + timestampStr;
                    logUnauthorizedAccess(message, requestContext);
                    throw new AccessUnauthorizedException(message);
                }
                if (replayAttackValidator.checkNonceReplay(nonce)) {
                    String message = "Unauthorized request (duplicated nonce): " + nonce;
                    logUnauthorizedAccess(message, requestContext);
                    throw new AccessUnauthorizedException();
                }
                requestContext.setEntityStream(new ByteArrayInputStream(contentData));
                Principal principal = findUserPrincipal(identity);
                if (principal == null) {
                    logUnauthorizedAccess("Unauthorized request (principal not found): " + identity, requestContext);
                    throw new AccessUnauthorizedException();
                }
                if (!verifySignature(principal, restRequestSigner.getDataToSign(), signature, requestContext)) {
                    logUnauthorizedAccess("Unauthorized request (invalid signature): " + restRequestSigner.toString(), requestContext);
                    throw new AccessUnauthorizedException();
                }
                updateAuthenticatedContext(requestContext, principal);
            } catch (ParseException e) {
                logBadRequest("Invalid timestamp: " + timestampStr, e, requestContext);
                throw new WebApplicationException(BAD_REQUEST);
            }
        } finally {
            try {
                MDC.remove(MDC_IDENTITY);
            } catch (IllegalArgumentException e) {
                //
            }
        }
    }

    protected void updateAuthenticatedContext(ContainerRequestContext requestContext, Principal principal) {
        RESTSecurityContext sc = new RESTSecurityContext(principal, requestContext.getSecurityContext().isSecure());
        requestContext.setSecurityContext(sc);
    }

    @Override
    public void aroundWriteTo(WriterInterceptorContext responseCtx) throws IOException, WebApplicationException {
        RequestDetails requestDetails = (RequestDetails) responseCtx.getProperty(TMP_REQDETAILS);
        if (requestDetails.principal != null) {
            ByteArrayOutputStream content = new ByteArrayOutputStream();
            OutputStream oldStream = responseCtx.getOutputStream();
            responseCtx.setOutputStream(content);
            responseCtx.proceed();
            byte[] contentData = content.toByteArray();
            RESTResponseSigner responseSigner = new RESTResponseSigner(requestDetails.nonce, requestDetails.signature, requestDetails.statusCode, contentData);
            try {
                List<Object> signatures = responseCtx.getHeaders().get(HEADER_SIGNATURE);
                if( signatures != null && !signatures.isEmpty() ) {
                    throw new IllegalStateException("Signature header already exists in response");
                }
                responseCtx.getHeaders().add(HEADER_SIGNATURE, signResponse(requestDetails.principal, responseSigner.getDataToSign()));
            } catch (InvalidKeyException e) {
                logServerError("Invalid key for identity " + requestDetails.identity + " : " + e.getMessage(), e, null);
                throw new WebApplicationException(INTERNAL_SERVER_ERROR);
            } catch (BackendAccessException e) {
                logServerError("Unexpected BackendAccessException" + e.getMessage(), e, null);
                throw new WebApplicationException(INTERNAL_SERVER_ERROR);
            }
            oldStream.write(contentData);
        }
    }

    @Override
    public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) throws IOException {
        RequestDetails requestDetails = new RequestDetails(requestContext.getHeaderString(HEADER_NONCE),
                requestContext.getHeaderString(HEADER_SIGNATURE), requestContext.getHeaderString(HEADER_IDENTITY),
                requestContext.getSecurityContext().getUserPrincipal(), responseContext.getStatus());
        responseContext.getHeaders().add(HEADER_TIMESTAMP, requestDetails.responseTimestamp);
        requestContext.setProperty(TMP_REQDETAILS, requestDetails);
        if (responseContext.getEntity() == null && requestDetails.principal != null) {
            try {
                RESTResponseSigner responseSigner = new RESTResponseSigner(requestDetails.nonce, requestDetails.signature, requestDetails.statusCode, null);
                responseContext.getHeaders().add(HEADER_SIGNATURE, signResponse(requestDetails.principal, responseSigner.getDataToSign()));
            } catch (InvalidKeyException e) {
                throw new UnexpectedException(e);
            }
        }
    }

    private boolean verifySignature(Principal principal, byte[] dataToSign, String signature, ContainerRequestContext requestContext) {
        try {
            final byte[] signatureData = StringUtils.base64Decode(signature);
            if (logger.isDebugEnabled()) {
                logger.debug("Verifying REST request - principal: " + principal + " data: " + fingerprint(dataToSign) + " signature: " + fingerprint(signatureData));
            }
            SignatureVerificationKey key = findVerificationKey(principal);
            if (key == null) {
                return false;
            }
            try {
                cryptoEngine.verifySignature(key, digestAlgorithm, dataToSign, signatureData);
                return true;
            } catch (InvalidKeyException e) {
                logServerError("Invalid key found while verifying signature: " + e.getMessage(), e, requestContext);
                throw new WebApplicationException(INTERNAL_SERVER_ERROR);
            } catch (SignatureException e) {
                return false;
            }
        } catch (BackendAccessException e) {
            logServerError("Unexpected BackendAccessException: " + e.getMessage(), e, requestContext);
            throw new WebApplicationException(INTERNAL_SERVER_ERROR);
        }
    }

    protected void logServerError(String message, Exception exception, ContainerRequestContext requestContext) {
        logger.error(message, exception);
    }

    protected void logUnauthorizedAccess(String message, ContainerRequestContext requestContext) {
        logger.warn(message);
    }

    protected void logBadRequest(String message, Exception exception, ContainerRequestContext requestContext) {
        logger.warn(message, exception);
    }

    protected void logUnauthorizedAccess(String message, Exception exception, ContainerRequestContext requestContext) {
        logger.warn(message, exception);
    }

    private String signResponse(Principal principal, byte[] data) throws InvalidKeyException, BackendAccessException {
        SigningKey key = findSigningKey(principal);
        if (key == null) {
            logServerError("Unable to find key for response signing: " + principal.getName(), null, null);
            throw new WebApplicationException(INTERNAL_SERVER_ERROR);
        }
        return StringUtils.base64Encode(cryptoEngine.sign(key, digestAlgorithm, data));
    }

    protected abstract Principal findUserPrincipal(String identity);

    protected abstract SignatureVerificationKey findVerificationKey(Principal principal) throws BackendAccessException;

    protected abstract SigningKey findSigningKey(Principal principal) throws BackendAccessException;

    public class RequestDetails {
        private String nonce;
        private String signature;
        private String identity;
        private String responseTimestamp;
        private Principal principal;
        private int statusCode;

        public RequestDetails(String nonce, String signature, String identity, Principal principal, int statusCode) {
            this.nonce = nonce;
            this.signature = signature;
            this.identity = identity;
            this.principal = principal;
            this.statusCode = statusCode;
            responseTimestamp = TimeUtils.formatISOUTCDateTime(new Date());
        }
    }
}
