package com.audax.userservice;

import com.audax.userservice.auth.AuthenticationRequest;
import com.audax.userservice.auth.AuthenticationResponse;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.data.mongo.DataMongoTest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
public class UserServiceIntegrationTests {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @BeforeEach
public void cleanupDB() {
    // Example: if you have a userRepository, you can clear all data like this:
    // userRepository.deleteAll();
}


    @Test
    public void testRegisterUser() {
        AuthenticationRequest request = new AuthenticationRequest();
        request.setEmail("test@test.com");
        request.setPassword("test1234");

        ResponseEntity<AuthenticationResponse> response = restTemplate.postForEntity("http://localhost:" + port + "/api/v1/auth/register", request, AuthenticationResponse.class);

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody().getMessage()).isEqualTo("Check your email for validation link!");
    }

    // ... similarly, you can add more tests for authenticate, verify email, password reset, etc.
}
