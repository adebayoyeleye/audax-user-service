package com.audax.userservice.auth;

import com.audax.userservice.user.Role;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationRequest {
    private String email;
    private String password;
    private String token;
    private String adminEmail;
    private Role role;
    private UserDetailsRequest userDetailsRequest;
}
