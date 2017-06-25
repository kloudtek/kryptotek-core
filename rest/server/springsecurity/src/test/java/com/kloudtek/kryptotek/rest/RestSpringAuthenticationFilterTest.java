package com.kloudtek.kryptotek.rest;

import com.kloudtek.kryptotek.CryptoUtils;
import com.kloudtek.kryptotek.rest.server.TestHelper;
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
import org.springframework.web.context.ContextLoaderListener;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.servlet.DispatcherServlet;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.IOException;
import java.security.InvalidKeyException;

import static com.kloudtek.kryptotek.rest.RESTRequestSigner.*;
import static com.kloudtek.kryptotek.rest.RESTRequestSigner.HEADER_SIGNATURE;
import static org.testng.Assert.*;

/**
 * Created by yannick on 6/24/17.
 */
public class RestSpringAuthenticationFilterTest {
    private Server server;
    private String url;
    private CloseableHttpClient httpClient;
    private TestHelper testHelper;

    @BeforeMethod
    public void init() throws Exception {
        server = new Server(0);
        AnnotationConfigWebApplicationContext springCtx = new AnnotationConfigWebApplicationContext();
        ServletContextHandler contextHandler = new ServletContextHandler(ServletContextHandler.SESSIONS);
        contextHandler.setContextPath("/");
        contextHandler.addServlet(new ServletHolder(new DispatcherServlet(springCtx)), "/*");
        contextHandler.addEventListener(new ContextLoaderListener(springCtx));
        server.setHandler(contextHandler);
        server.start();
        url = "http://localhost:" + ((ServerConnector) server.getConnectors()[0]).getLocalPort();
        testHelper = new TestHelper(url);
    }


    @Test
    public void testValidHmac() throws IOException, InvalidKeyException {
        testHelper.testValidHmac();
    }
}