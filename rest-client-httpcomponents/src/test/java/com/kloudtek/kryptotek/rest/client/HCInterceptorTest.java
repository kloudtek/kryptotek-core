/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.rest.client;

import com.kloudtek.kryptotek.CryptoUtils;
import com.kloudtek.kryptotek.DigestAlgorithm;
import com.kloudtek.util.StringUtils;
import com.kloudtek.util.TimeUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.Date;

import static com.kloudtek.util.StringUtils.utf8;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.fail;

public class HCInterceptorTest {
    public static final String IDENTITY = "user";
    public static final String PATH = "/test/afdsfdsafsda?a=b";
    private static final String HMAC_KEY_B64 = "cni1ZN5Q3HKv8KAbPy878xWnJzwE/3MyG9vU3M5MAOHiLJXJVeYCnNQVN6e7H/T7mo7EJn3ATLOIjtGJwPkOvA==";
    private static final SecretKey HMAC_KEY = new SecretKeySpec(StringUtils.base64Decode(HMAC_KEY_B64),"RAW");
    private static final byte[] DATA = "safdfsa893wfjsafj893q2fjidwaqjf8913rjo14879fsdkjdl".getBytes();
    private CloseableHttpClient httpClient;
    private Server server;
    private String url;
    private TestServlet servlet;

    @BeforeTest
    public void setup() throws Exception {
        httpClient = new HmacHCInterceptor(DigestAlgorithm.SHA1, IDENTITY, HMAC_KEY).createClientBuilder().build();
        server = new Server(0);
        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
        context.setContextPath("/test/");
        servlet = new TestServlet();
        context.addServlet(new ServletHolder(servlet),"/*");
        server.setHandler(context);
        server.start();
        url = "http://localhost:"+((ServerConnector) server.getConnectors()[0]).getLocalPort();
    }

    @AfterTest
    public void cleanup() throws Exception {
        httpClient.close();
        server.stop();
    }

    @Test
    public void testStandard() throws Exception {
        HttpPost post = new HttpPost(url + PATH);
        post.setEntity(new ByteArrayEntity(DATA));
        CloseableHttpResponse response = httpClient.execute(post);
        assertEquals(200, response.getStatusLine().getStatusCode());
    }

    @Test
    public void testTimeOutOfSync() throws Exception {
        HttpPost post = new HttpPost(url + PATH);
        post.setEntity(new ByteArrayEntity(DATA));
        CloseableHttpResponse response = httpClient.execute(post);
        assertEquals(200, response.getStatusLine().getStatusCode());
    }

    public class TestServlet extends HttpServlet {
        private static final long serialVersionUID = -2507734802640341400L;

        @Override
        protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            String nounce = req.getHeader("X-NOUNCE");
            String timestampStr = req.getHeader("X-TIMESTAMP");
            ByteArrayOutputStream dataToSign = new ByteArrayOutputStream();
            addSigData(dataToSign,"POST",PATH,nounce,timestampStr,"user");
            dataToSign.write(DATA);
            dataToSign.close();
            String authz = req.getHeader("AUTHORIZATION");
            try {
                assertEquals(authz, StringUtils.base64Encode(CryptoUtils.hmacSha1(HMAC_KEY, dataToSign.toByteArray())));
            } catch (InvalidKeyException e) {
                fail(e.getMessage(),e);
            }
        }

        private void addSigData(ByteArrayOutputStream dataToSign, String... data) throws IOException {
            for (String d : data) {
                dataToSign.write(utf8(d));
                dataToSign.write(0);
            }
        }
    }

    public class TimeServlet extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            long time = System.currentTimeMillis() + 1000000L;
            String timeStr = TimeUtils.formatISOUTCDateTime(new Date(time));
            resp.setContentLength(timeStr.length());
            resp.getWriter().write(timeStr);
        }
    }
}