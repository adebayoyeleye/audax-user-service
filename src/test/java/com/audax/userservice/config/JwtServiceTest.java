package com.audax.userservice.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
// import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import com.audax.userservice.user.Role;
import com.audax.userservice.user.User;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.HashSet;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;

@ExtendWith(MockitoExtension.class)
class JwtServiceTest {

    private JwtService jwtService;
    String mockSecretKey = "ca288b9d9b63ad6a7f895c6ebe1f3820cf8dc5c88ea1b64740ab2661a43241cf";

    private final String EMAIL = "test@email.com";
    private final String PASSWORD = "password";
    private String TOKEN;
    private User sampleUser;

    @BeforeEach
    void setUp() {
        TOKEN = null;
        jwtService = new JwtService(mockSecretKey);
        // ReflectionTestUtils.setField(jwtService, "SECRET_KEY", mockSecretKey);
        sampleUser = User.builder()
                .email(EMAIL)
                .password(PASSWORD)
                .roles(new HashSet<>(List.of(Role.USER)))
                .build();
        TOKEN = jwtService.generateToken(sampleUser);
        System.out.println(TOKEN);

    }

    @Test
    void generateToken_withUserDetails_shouldReturnJwtToken() {
        assertFalse(TOKEN.isEmpty());
    }

    @Test
    void extractUsername_withValidToken_shouldReturnUsername() {
        String username = jwtService.extractUsername(TOKEN);
        assertEquals(EMAIL, username);
    }

    // @Test
    // void isTokenExpired_withExpiredToken_shouldReturnTrue() {
    // // Arrange
    // String token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.e1234567890";

    // // Act
    // boolean isExpired = jwtService.isTokenExpired(token);

    // // Assert
    // assertTrue(isExpired);
    // }

    // @Test
    // void isTokenValid_withValidTokenAndUserDetails_shouldReturnTrue() {
    // // Arrange
    // String token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.e1234567890";
    // UserDetails userDetails = new UserDetails("johndoe", "password", new
    // HashSet<>(List.of(Role.USER)));

    // // Act
    // boolean isValid = jwtService.isTokenValid(token, userDetails);

    // // Assert
    // assertTrue(isValid);
    // }

    // @Test
    // void isTokenValid_withValidTokenAndInvalidUserDetails_shouldReturnFalse() {
    // // Arrange
    // String token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.e1234567890";
    // UserDetails userDetails = new UserDetails("janedoe", "password", new
    // HashSet<>(List.of(Role.USER)));

    // // Act
    // boolean isValid = jwtService.isTokenValid(token, userDetails);

    // // Assert
    // assertFalse(isValid);
    // }

}