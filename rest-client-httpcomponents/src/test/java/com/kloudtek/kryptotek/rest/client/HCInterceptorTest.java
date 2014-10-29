/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.rest.client;

import com.kloudtek.kryptotek.CryptoUtils;
import com.kloudtek.kryptotek.DigestAlgorithm;
import com.kloudtek.kryptotek.rest.RESTRequestSigner;
import com.kloudtek.kryptotek.rest.RESTResponseSigner;
import com.kloudtek.kryptotek.rest.client.httpcomponents.HmacHCInterceptor;
import com.kloudtek.kryptotek.rest.client.httpcomponents.TimeAsHttpContentTimeSync;
import com.kloudtek.util.StringUtils;
import com.kloudtek.util.TimeUtils;
import org.apache.http.HttpException;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.testng.annotations.*;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Date;

import static com.kloudtek.kryptotek.rest.RESTRequestSigner.HEADER_NOUNCE;
import static com.kloudtek.kryptotek.rest.RESTRequestSigner.HEADER_SIGNATURE;
import static com.kloudtek.kryptotek.rest.RESTRequestSigner.HEADER_TIMESTAMP;
import static com.kloudtek.util.StringUtils.utf8;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

public class HCInterceptorTest {
    public static final String IDENTITY = "user";
    public static final String TEST_SERVLET_PATH = "/afdsfdsafsda";
    public static final String TEST_SERVLET_PATH_FULL = "/test/afdsfdsafsda?a=b";
    private static final String HMAC_KEY_B64 = "cni1ZN5Q3HKv8KAbPy878xWnJzwE/3MyG9vU3M5MAOHiLJXJVeYCnNQVN6e7H/T7mo7EJn3ATLOIjtGJwPkOvA==";
    private static final SecretKey HMAC_KEY = new SecretKeySpec(StringUtils.base64Decode(HMAC_KEY_B64), "RAW");
    private static final byte[] DATA = "safdfsa893wfjsafj893q2fjidwaqjf8913rjo14879fsdkjdl".getBytes();
    private static final byte[] DATA_RESP = "fs7fyw3jkfh8sjwqafliu8rujlsajf".getBytes();
    public static final String TIME_PATH = "/time";
    public static final String TIME_PATH_FULL = "/test/time";
    private CloseableHttpClient httpClient;
    private Server server;
    private String url;
    private TestServlet testServlet;
    private TimeServlet timeServlet;

    @BeforeMethod
    public void setup() throws Exception {
        server = new Server(0);
        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
        context.setContextPath("/test/");
        testServlet = new TestServlet();
        timeServlet = new TimeServlet();
        context.addServlet(new ServletHolder(testServlet), TEST_SERVLET_PATH);
        context.addServlet(new ServletHolder(timeServlet), TIME_PATH);
        server.setHandler(context);
        server.start();
        url = "http://localhost:" + ((ServerConnector) server.getConnectors()[0]).getLocalPort();
    }

    @AfterMethod
    public void cleanup() throws Exception {
        httpClient.close();
        server.stop();
    }

    @Test
    public void testHmac() throws Exception {
        httpClient = new HmacHCInterceptor(DigestAlgorithm.SHA1, IDENTITY, HMAC_KEY, null, null).createClient();
        HttpPost post = new HttpPost(url + TEST_SERVLET_PATH_FULL);
        post.setEntity(new ByteArrayEntity(DATA));
        CloseableHttpResponse response = httpClient.execute(post);
        assertEquals(200, response.getStatusLine().getStatusCode());
    }

    @Test
    public void timeHmacTimeOutSync() throws Exception {
        testServlet.timeSlip = 100000L;
        timeServlet.timeSlip = 100000L;
        httpClient = new HmacHCInterceptor(DigestAlgorithm.SHA1, IDENTITY, HMAC_KEY, new TimeAsHttpContentTimeSync(url + TIME_PATH_FULL), null).createClient();
        HttpPost post = new HttpPost(url + TEST_SERVLET_PATH_FULL);
        post.setEntity(new ByteArrayEntity(DATA));
        CloseableHttpResponse response = httpClient.execute(post);
        assertEquals(200, response.getStatusLine().getStatusCode());
    }

    @Test
    public void testHmacInvalidReply() throws Exception {
        testServlet.badReply = true;
        httpClient = new HmacHCInterceptor(DigestAlgorithm.SHA1, IDENTITY, HMAC_KEY, null, null).createClient();
        HttpPost post = new HttpPost(url + TEST_SERVLET_PATH_FULL);
        post.setEntity(new ByteArrayEntity(DATA));
        try {
            httpClient.execute(post);
        } catch (ClientProtocolException e) {
            Throwable cause = e.getCause();
            if( cause instanceof HttpException && cause.getMessage().equals("Invalid response signature") ) {
                return;
            }
        }
        fail("Did not get expected error");
    }

    public class TestServlet extends HttpServlet {
        private static final long serialVersionUID = -2507734802640341400L;
        private Date timestamp;
        private long timeSlip = 0;
        private boolean badReply;

        @Override
        protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            super.service(req, resp);
        }

        @Override
        protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            try {
                String nounce = req.getHeader(HEADER_NOUNCE);
                String timestampStr = req.getHeader(HEADER_TIMESTAMP);
                timestamp = TimeUtils.parseISOUTCDateTime(timestampStr);
                long expectedTimestamp = System.currentTimeMillis() + timeSlip;
                long diff = timestamp.getTime() - expectedTimestamp;
                if( diff > 2000L || diff < -2000L ) {
                    fail("Time difference too large: "+diff);
                }
                RESTRequestSigner requestSigner = new RESTRequestSigner("POST",TEST_SERVLET_PATH_FULL,nounce,timestampStr, "user");
                requestSigner.setContent(DATA);
                String authz = req.getHeader(HEADER_SIGNATURE);
                assertEquals(authz, StringUtils.base64Encode(CryptoUtils.hmacSha1(HMAC_KEY, requestSigner.getDataToSign())));
                RESTResponseSigner responseSigner = new RESTResponseSigner(authz, 200);
                responseSigner.setContent(badReply ? "fdsafads".getBytes() : DATA_RESP);
                resp.setHeader(HEADER_SIGNATURE, StringUtils.base64Encode(CryptoUtils.hmacSha1(HMAC_KEY, responseSigner.getDataToSign())));
                resp.getOutputStream().write(DATA_RESP);
            } catch (Exception e) {
                fail(e.getMessage(), e);
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
        private long timeSlip = 0;

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            long time = System.currentTimeMillis() + timeSlip;
            String timeStr = TimeUtils.formatISOUTCDateTime(new Date(time));
            resp.setContentLength(timeStr.length());
            resp.getWriter().write(timeStr);
        }
    }
}