/*
 * Copyright (c) 2015 Kloudtek Ltd
 */

package com.kloudtek.kryptotek.rest.server.jaxrs;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * Created by yannick on 10/03/2015.
 */
public class AccessUnauthorizedException extends WebApplicationException {
    public AccessUnauthorizedException() {
        super(Response.status(Response.Status.UNAUTHORIZED)
                .type(MediaType.TEXT_PLAIN).build());
    }
}
