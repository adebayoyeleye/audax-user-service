package com.audax.userservice.auth.exceptions;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(value = { UsernameNotFoundException.class })
    protected ResponseEntity<Map<String, Object>> handleUsernameNotFoundException(UsernameNotFoundException ex) {
        LOGGER.error("User not found", ex);
        return buildResponse("User not found", HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(value = { DuplicateEmailException.class })
    protected ResponseEntity<Map<String, Object>> handleDuplicateEmailException(DuplicateEmailException ex) {
        LOGGER.error("Attempt to register with already used email", ex);
        return buildResponse("Email already used", HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(value = { InvalidTokenException.class })
    protected ResponseEntity<Map<String, Object>> handleInvalidTokenException(InvalidTokenException ex) {
        LOGGER.error("Invalid token", ex);
        return buildResponse("Invalid token", HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(value = { AccountNotEnabled.class })
    protected ResponseEntity<Map<String, Object>> handleAccountNotEnabled(AccountNotEnabled ex) {
        LOGGER.error("Account not enabled", ex);
        return buildResponse("The account has not been enabled. Please check your email for a verification link.",
                HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(value = { UnauthorizedException.class })
    protected ResponseEntity<Map<String, Object>> handleUnauthorizedException(UnauthorizedException ex) {
        LOGGER.error("Account not authorized", ex);
        return buildResponse("Account not authorized", HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(value = { RuntimeException.class })
    protected ResponseEntity<Map<String, Object>> handleRuntimeException(RuntimeException ex) {
        LOGGER.error("Internal server error", ex);
        return buildResponse("Internal server error", HttpStatus.INTERNAL_SERVER_ERROR);
    }

    private ResponseEntity<Map<String, Object>> buildResponse(String message, HttpStatus status) {
        Map<String, Object> body = new HashMap<>();
        body.put("timestamp", LocalDateTime.now());
        body.put("message", message);
        return new ResponseEntity<>(body, status);
    }
}
