package com.audax.userservice.auth;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService service;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody UserDetailsRequest request) {
        return ResponseEntity.ok(service.register(request));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationRequest request) {
        return ResponseEntity.ok(service.authenticate(request));
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
