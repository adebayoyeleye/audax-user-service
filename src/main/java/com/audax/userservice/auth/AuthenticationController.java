package com.audax.userservice.auth;

import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService service;

    // @PostMapping("/register")
    // public ResponseEntity<AuthenticationResponse> register(
    // @RequestBody UserDetailsRequest request) {
    // return ResponseEntity.ok(service.register(request));
    // }

    // @PostMapping("/authenticate")
    // public ResponseEntity<AuthenticationResponse> authenticate(
    // @RequestBody AuthenticationRequest request) {
    // return ResponseEntity.ok(service.authenticate(request));
    // }

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody UserDetailsRequest request, HttpServletResponse response) {
        Map<String, Object> result = service.register(request);

        // Get the authentication response and cookie from the map
        AuthenticationResponse authResponse = (AuthenticationResponse) result.get("authResponse");
        Cookie jwtCookie = (Cookie) result.get("jwtCookie");

        response.addCookie(jwtCookie);
        return ResponseEntity.ok(authResponse);

        // AuthenticationResponse authResponse = service.register(request);
        // response.addCookie(authResponse.getCookie());
        // return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationRequest request, HttpServletResponse response) {
        AuthenticationResponse authResponse = service.authenticate(request);
        response.addCookie(authResponse.getCookie());
        return ResponseEntity.ok(authResponse);
    }

    @GetMapping("/logout")
    public ResponseEntity<AuthenticationResponse> logout(HttpServletResponse response) {
        AuthenticationResponse authResponse = service.logout();
        response.addCookie(authResponse.getCookie());
        return ResponseEntity.ok(authResponse);
    }

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
