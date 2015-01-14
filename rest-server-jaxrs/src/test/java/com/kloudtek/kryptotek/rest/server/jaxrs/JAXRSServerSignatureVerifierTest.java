/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.rest.server.jaxrs;

import com.kloudtek.kryptotek.CryptoUtils;
import com.kloudtek.kryptotek.jce.JCEHMACSHA1Key;
import com.kloudtek.kryptotek.key.HMACKey;
import com.kloudtek.kryptotek.rest.RESTRequestSigner;
import com.kloudtek.kryptotek.rest.RESTResponseSigner;
import com.kloudtek.util.StringUtils;
import com.kloudtek.util.io.IOUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.jboss.resteasy.plugins.server.servlet.HttpServletDispatcher;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.logging.Logger;

import static com.kloudtek.kryptotek.rest.RESTRequestSigner.*;

public class JAXRSServerSignatureVerifierTest {
    private static final Logger logger = Logger.getLogger(JAXRSServerSignatureVerifierTest.class.getName());
    public static final String HMAC_KEY_B64 = "cni1ZN5Q3HKv8KAbPy878xWnJzwE/3MyG9vU3M5MAOHiLJXJVeYCnNQVN6e7H/T7mo7EJn3ATLOIjtGJwPkOvA==";
    public static final HMACKey HMAC_KEY = new JCEHMACSHA1Key(null,new SecretKeySpec(StringUtils.base64Decode(HMAC_KEY_B64), "RAW"));
    public static final String DATA_STR = "blabla";
    public static final byte[] DATA = DATA_STR.getBytes();
    public static final String PATH = "/test/dostuff?x=" + StringUtils.urlEncode("a b");
    private String url;
    private Server server;
    private CloseableHttpClient httpClient;
    public static final String USER = "user";

    @BeforeMethod
    public void init() throws Exception {
        server = new Server(0);
        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
        context.setContextPath("/");
        ServletHolder h = new ServletHolder(new HttpServletDispatcher());
        h.setInitParameter("javax.ws.rs.Application", TestApp.class.getName());
        context.addServlet(h, "/*");
        server.setHandler(context);
        server.start();
        url = "http://localhost:" + ((ServerConnector) server.getConnectors()[0]).getLocalPort();
        httpClient = HttpClientBuilder.create().build();
    }

    @AfterClass
    public void close() throws Exception {
        server.stop();
    }

    @Test
    public void testValidHmac() throws IOException, InvalidKeyException {
        RESTRequestSigner restRequestSigner = new RESTRequestSigner("POST", PATH, 0, USER, DATA);
        HttpPost request = new HttpPost(url + PATH);
        request.setHeader(HEADER_IDENTITY, restRequestSigner.getIdentity());
        request.setHeader(HEADER_NOUNCE, restRequestSigner.getNounce());
        request.setHeader(HEADER_TIMESTAMP, restRequestSigner.getTimestamp());
        String signature = StringUtils.base64Encode(CryptoUtils.sign(HMAC_KEY, restRequestSigner.getDataToSign()));
        request.setHeader(HEADER_SIGNATURE, signature);
        restRequestSigner.setContent(DATA);
        request.setEntity(new ByteArrayEntity(DATA));
        logger.info(restRequestSigner.toString());
        CloseableHttpResponse response = httpClient.execute(request);
        Assert.assertEquals(response.getStatusLine().getStatusCode(), 200);
        byte[] responseData = IOUtils.toByteArray(response.getEntity().getContent());
        Assert.assertEquals(new String(responseData), "{\"a\":\"b\",\"b\":\"c\"}");
        String expectedSig = StringUtils.base64Encode(CryptoUtils.sign(HMAC_KEY, new RESTResponseSigner(restRequestSigner.getNounce(), signature, 200, responseData).getDataToSign()));
        Assert.assertEquals(response.getFirstHeader(HEADER_SIGNATURE).getValue(),expectedSig);
    }
}