package com.kloudtek.kryptotek.rest;

/**
 * Created by yannick on 6/25/17.
 */
public class AuthenticationFailedException extends Exception {
    private Object requestObj;

    public AuthenticationFailedException(Object requestObj) {
        this.requestObj = requestObj;
    }

    public AuthenticationFailedException(String message, Object requestObj) {
        super(message);
        this.requestObj = requestObj;
    }

    public AuthenticationFailedException(String message, Throwable cause, Object requestObj) {
        super(message, cause);
        this.requestObj = requestObj;
    }

    public AuthenticationFailedException(Throwable cause, Object requestObj) {
        super(cause);
        this.requestObj = requestObj;
    }
}
