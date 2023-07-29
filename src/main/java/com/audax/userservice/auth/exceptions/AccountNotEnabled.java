package com.audax.userservice.auth.exceptions;

public class AccountNotEnabled extends AuthenticationException {
    public AccountNotEnabled(String message) {
        super(message);
    }
}
