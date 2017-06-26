package com.kloudtek.kryptotek.rest;

import com.kloudtek.util.InvalidBackendDataException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ReadListener;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.security.Principal;

import static com.kloudtek.kryptotek.rest.RESTRequestSigner.*;
import static com.kloudtek.kryptotek.rest.SpringAuthenticationFilterHelper.STREAM_ATTR;

/**
 * Created by yannick on 6/21/17.
 */
public class RestSpringAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    private SpringAuthenticationFilterHelper springAuthenticationFilterHelper;

    public RestSpringAuthenticationFilter(RequestMatcher requiresAuthenticationRequestMatcher, SpringAuthenticationFilterHelper springAuthenticationFilterHelper) {
        super(requiresAuthenticationRequestMatcher);
        this.springAuthenticationFilterHelper = springAuthenticationFilterHelper;
        setContinueChainBeforeSuccessfulAuthentication(false);
    }

    public RestSpringAuthenticationFilter(SpringAuthenticationFilterHelper springAuthenticationFilterHelper) {
        this(new AntPathRequestMatcher("/**"), springAuthenticationFilterHelper);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            String nonce = request.getHeader(HEADER_NONCE);
            String identity = request.getHeader(HEADER_IDENTITY);
            String timestampStr = request.getHeader(HEADER_TIMESTAMP);
            String signature = request.getHeader(HEADER_SIGNATURE);
            try {
                Principal principal = springAuthenticationFilterHelper.authenticateRequest(request.getInputStream(), nonce, identity, timestampStr,
                        signature, request.getMethod(), request.getRequestURI(), request.getQueryString(), request);
                System.out.println();
            } catch (AuthenticationFailedException e) {
                switch (e.getReason()) {
                    case USER_NOT_FOUND:
                        throw new UsernameNotFoundException(e.getMessage(), e);
                    case INVALID_SIGNATURE:
                        throw new BadCredentialsException(e.getMessage(), e);
                    default:
                        throw new AuthenticationServiceException(e.getMessage(), e);
                }
            } catch (InvalidRequestException e) {
                throw new BadCredentialsException(e.getMessage(), e);
            } catch (InvalidBackendDataException e) {
                throw new AuthenticationServiceException(e.getMessage(), e);
            }
        }
        return null;
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        InputStream stream = (InputStream) request.getAttribute(STREAM_ATTR);
        if( stream != null ) {
            request.removeAttribute(STREAM_ATTR);
            chain.doFilter(new RequestWrapper(request, stream), response);
        } else {
            chain.doFilter(request, response);
        }
        super.successfulAuthentication(request, response, chain, authResult);
    }

    public class RequestWrapper extends HttpServletRequestWrapper {
        private StreamWrapper stream;

        public RequestWrapper(HttpServletRequest request, InputStream stream) {
            super(request);
            this.stream = new StreamWrapper(stream);
        }

        @Override
        public ServletInputStream getInputStream() throws IOException {
            return stream;
        }
    }

    public class StreamWrapper extends ServletInputStream {
        private InputStream is;
        private boolean finished;
        private ReadListener readListener;

        public StreamWrapper(InputStream is) {
            this.is = is;
        }

        @Override
        public boolean isFinished() {
            return finished;
        }

        @Override
        public boolean isReady() {
            return true;
        }

        @Override
        public void setReadListener(ReadListener readListener) {
            this.readListener = readListener;
        }

        @Override
        public int read() throws IOException {
            try {
                int read = is.read();
                if( read == -1 ) {
                    finished = true;
                    if( readListener != null ) {
                        readListener.onAllDataRead();
                    }
                }
                return read;
            } catch (IOException e) {
                if( readListener != null ) {
                    readListener.onError(e);
                }
                throw e;
            }
        }
    }
}
