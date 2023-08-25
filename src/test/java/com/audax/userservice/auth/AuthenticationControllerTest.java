package com.audax.userservice.auth;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@ActiveProfiles("test")
@AutoConfigureMockMvc
public class AuthenticationControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AuthenticationService authenticationService;

    private ObjectMapper objectMapper = new ObjectMapper();

    private final String EMAIL = "test@email.com";
    private final String PASSWORD = "password";

    @BeforeEach
    public void setUp() {
        // Initialize mock return values or behavior here if needed
    }

    @Test
    public void testRegister() throws Exception {
        UserDetailsRequest userDetails = new UserDetailsRequest();
        userDetails.setEmail(EMAIL);
        userDetails.setPassword(PASSWORD);
        
        AuthenticationResponse mockResponse = AuthenticationResponse.builder()
            .message("Check your email for validation link!")
            .build();

        when(authenticationService.register(any(UserDetailsRequest.class)))
            .thenReturn(mockResponse);

        mockMvc.perform(post("/api/v1/auth/register")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(userDetails)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.message").value("Check your email for validation link!"));
    }

    // Similar structure for other endpoints like authenticate, verifyEmail, etc.
}


// public class AuthenticationControllerTest {
//     @Test
//     void testAuthenticate() {

//     }

//     @Test
//     void testInitiatePasswordReset() {

//     }

//     @Test
//     void testRegister() {

//     }

//     @Test
//     void testResetPassword() {

//     }

//     @Test
//     void testUpdateUserProfile() {

//     }

//     @Test
//     void testUpdateUserRole() {

//     }

//     @Test
//     void testVerifyEmail() {

//     }
// }
