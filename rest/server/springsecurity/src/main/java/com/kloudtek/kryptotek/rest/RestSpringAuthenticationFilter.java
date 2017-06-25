package com.kloudtek.kryptotek.rest;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * Created by yannick on 6/21/17.
 */
public class RestSpringAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
//            String method = method;
//            RESTRequestSigner restRequestSigner = new RESTRequestSigner(method, path.toString(), nonce, timestampStr, identity);

        }
    }
}
