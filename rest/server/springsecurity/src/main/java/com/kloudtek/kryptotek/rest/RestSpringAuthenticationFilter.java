package com.kloudtek.kryptotek.rest;

import com.kloudtek.util.InvalidBackendDataException;
import com.kloudtek.util.TimeUtils;
import com.kloudtek.util.io.BoundedOutputStream;
import com.kloudtek.util.io.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.annotation.PostConstruct;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Principal;
import java.util.Date;

import static com.kloudtek.kryptotek.rest.RESTRequestSigner.*;

/**
 * Created by yannick on 6/21/17.
 */
public class RestSpringAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private SpringAuthenticationFilterHelper springAuthenticationFilterHelper;

    public RestSpringAuthenticationFilter(@Autowired SpringAuthenticationFilterHelper springAuthenticationFilterHelper ) {
        this.springAuthenticationFilterHelper = springAuthenticationFilterHelper;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            String nonce = httpRequest.getHeader(HEADER_NONCE);
            String identity = httpRequest.getHeader(HEADER_IDENTITY);
            String timestampStr = httpRequest.getHeader(HEADER_TIMESTAMP);
            String signature = httpRequest.getHeader(HEADER_SIGNATURE);
        }
    }
}
