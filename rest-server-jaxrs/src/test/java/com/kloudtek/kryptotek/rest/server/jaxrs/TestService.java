/*
 * Copyright (c) 2014 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.rest.server.jaxrs;

import com.kloudtek.util.io.IOUtils;
import org.testng.Assert;

import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import java.io.IOException;
import java.io.InputStream;
import java.util.logging.Logger;

/**
 * Created by yannick on 29/10/2014.
 */
@Path("/test")
public class TestService {
    private static final Logger logger = Logger.getLogger(TestService.class.getName());
    @Path("/dostuff")
    @POST
    @Produces("text/plain")
    public String doStuff( @QueryParam("x") String x, InputStream content) throws IOException {
        Assert.assertEquals(x,"a b");
        String contentData = IOUtils.toString(content);
        Assert.assertEquals(contentData,JAXRSServerSignatureVerifierTest.DATA_STR);
        return "xxx";
    }
}
