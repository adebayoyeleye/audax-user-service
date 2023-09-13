package com.audax.userservice.auth;

import com.audax.userservice.auth.AuthenticationService.UserRecord;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationResponse {
    private String token;
    private String message;
    private UserRecord user;
}
