package com.audax.userservice.auth;

import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService service;

    // @GetMapping("/csrf")
    // public CsrfToken csrf(CsrfToken csrfToken) {
    //     return csrfToken;
    // }

    @GetMapping("/getcurrentuser")
    public ResponseEntity<AuthenticationResponse> getCurrentUser(HttpServletRequest request) {
        AuthenticationResponse authResponse = service.getCurrentUser(request);
        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody UserDetailsRequest request, HttpServletResponse response) {
        Map<String, Object> result = service.register(request);

        // Get the authentication response and cookie from the map
        AuthenticationResponse authResponse = (AuthenticationResponse) result.get("authResponse");
        Cookie jwtCookie = (Cookie) result.get("jwtCookie");

        response.addCookie(jwtCookie);
        return ResponseEntity.ok(authResponse);

    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationRequest request, HttpServletResponse response) {

         Map<String, Object> result = service.authenticate(request);

        // Get the authentication response and cookie from the map
        AuthenticationResponse authResponse = (AuthenticationResponse) result.get("authResponse");
        Cookie jwtCookie = (Cookie) result.get("jwtCookie");

        response.addCookie(jwtCookie);
        return ResponseEntity.ok(authResponse);
    }

    // @GetMapping("/logout")
    // public ResponseEntity<AuthenticationResponse> logout(HttpServletResponse response) {
    //     AuthenticationResponse authResponse = service.logout();
    //     response.addCookie(authResponse.getCookie());
    //     return ResponseEntity.ok(authResponse);
    // }

    @PostMapping("/verify-email")
    public ResponseEntity<AuthenticationResponse> verifyEmail(
            @RequestBody AuthenticationRequest request) {
        return ResponseEntity.ok(service.verifyEmail(request));
    }

    @PostMapping("/init-password-reset")
    public ResponseEntity<AuthenticationResponse> initiatePasswordReset(
            @RequestBody AuthenticationRequest request) {
        return ResponseEntity.ok(service.initiatePasswordReset(request));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<AuthenticationResponse> resetPassword(
            @RequestBody AuthenticationRequest request) {
        return ResponseEntity.ok(service.resetPassword(request));
    }

    @PutMapping("/update-user")
    public ResponseEntity<AuthenticationResponse> updateUserProfile(
            @RequestBody AuthenticationRequest request) {
        return ResponseEntity.ok(service.updateUserProfile(request));
    }

    @PutMapping("/update-role")
    public ResponseEntity<AuthenticationResponse> updateUserRole(
            @RequestBody AuthenticationRequest request) {
        return ResponseEntity.ok(service.updateUserRole(request));
    }
}
