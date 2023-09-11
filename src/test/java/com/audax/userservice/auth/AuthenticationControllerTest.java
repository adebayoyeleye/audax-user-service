// package com.audax.userservice.auth;

// import static org.mockito.ArgumentMatchers.any;
// import static org.mockito.ArgumentMatchers.eq;
// import static org.mockito.Mockito.*;
// import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
// import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

// import java.time.LocalDateTime;
// import java.util.HashMap;
// import java.util.HashSet;
// import java.util.List;
// import java.util.Map;
// import java.util.UUID;

// import com.audax.userservice.config.JwtService;
// import com.audax.userservice.user.Role;
// import com.audax.userservice.user.User;
// import com.fasterxml.jackson.databind.ObjectMapper;

// import jakarta.servlet.Filter;
// import jakarta.servlet.http.Cookie;

// import org.junit.jupiter.api.BeforeEach;
// import org.junit.jupiter.api.Test;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.beans.factory.annotation.Qualifier;
// import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
// import org.springframework.boot.test.context.SpringBootTest;
// import org.springframework.boot.test.mock.mockito.MockBean;
// import org.springframework.http.MediaType;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.security.core.userdetails.UserDetailsService;
// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.test.context.ActiveProfiles;
// import org.springframework.test.web.servlet.MockMvc;
// import org.springframework.test.web.servlet.setup.MockMvcBuilders;
// import org.springframework.web.context.WebApplicationContext;

// @SpringBootTest
// @ActiveProfiles("test")
// @AutoConfigureMockMvc
// public class AuthenticationControllerTest {

//     @Autowired
//     private MockMvc mockMvc;

//     @Autowired
//     private WebApplicationContext context;

//     @Autowired
//     @Qualifier("springSecurityFilterChain")
//     private Filter csrfFilter;

//     @Autowired
//     private JwtService jwtService;
//     @Autowired
//     private PasswordEncoder passwordEncoder;

//     @MockBean
//     private UserDetailsService userDetailsService;

//     @MockBean
//     private AuthenticationService authenticationService;

//     private ObjectMapper objectMapper = new ObjectMapper();

//     private final String EMAIL = "test@email.com";
//     private final String PASSWORD = "password";
//     UserDetailsRequest userDetails;

//     private String jwtToken;

//     @BeforeEach
//     public void setUp() {
//         // Initialize mock return values or behavior here if needed
//         userDetails = new UserDetailsRequest();
//         userDetails.setEmail(EMAIL);
//         userDetails.setPassword(PASSWORD);

//         var user = User.builder()
//                 .email(userDetails.getEmail())
//                 .password(passwordEncoder.encode(userDetails.getPassword()))
//                 // .password(userDetails.getPassword())
//                 .roles(new HashSet<>(List.of(Role.USER)))
//                 .isAccountNonLocked(true)
//                 .isAccountNonExpired(true)
//                 .isCredentialsNonExpired(true)
//                 .isEnabled(false)
//                 .emailVerificationToken(UUID.randomUUID().toString())
//                 .createdAt(LocalDateTime.now())
//                 .build();

//         jwtToken = jwtService.generateToken(user);

//         // jwtToken = "mockJwtToken"; // This is a mocked JWT token for testing

//         // when(jwtService.generateToken(any(User.class))).thenReturn(jwtToken);
//         // when(jwtService.extractUsername(eq(jwtToken))).thenReturn(EMAIL);
//         // when(jwtService.isTokenValid(eq(jwtToken),
//         // any(UserDetails.class))).thenReturn(true);
//         when(userDetailsService.loadUserByUsername(EMAIL)).thenReturn(user);

//         mockMvc = MockMvcBuilders
//                 .webAppContextSetup(context)
//                 .addFilters(csrfFilter) // Apply CSRF tokens handling
//                 .build();
//     }

//     @Test
//     public void testRegister() throws Exception {
//         // UserDetailsRequest userDetails = new UserDetailsRequest();
//         // userDetails.setEmail(EMAIL);
//         // userDetails.setPassword(PASSWORD);

//         AuthenticationResponse mockResponse = AuthenticationResponse.builder()
//                 .message("Check your email for validation link!")
//                 .build();

//         // Construct the mock map to be returned by the service
//         Map<String, Object> mockServiceResult = new HashMap<>();
//         mockServiceResult.put("authResponse", mockResponse);
//         mockServiceResult.put("jwtCookie", new Cookie("JWT-TOKEN", jwtToken)); // Add a mock cookie

//         when(authenticationService.register(any(UserDetailsRequest.class)))
//                 .thenReturn(mockServiceResult);

//         // when(authenticationService.register(any(UserDetailsRequest.class)))
//         // .thenReturn(mockResponse);

//         mockMvc.perform(post("/api/v1/auth/register")
//                 .contentType(MediaType.APPLICATION_JSON)
//                 .content(objectMapper.writeValueAsString(userDetails)))
//                 .andExpect(status().isOk())
//                 .andExpect(jsonPath("$.message").value("Check your email for validation link!"));
//     }

//     @Test
//     public void testAuthenticate() throws Exception {
//         // ... Set up data and mock responses
//         AuthenticationResponse mockResponse = AuthenticationResponse.builder()
//                 .cookie(new Cookie("JWT-TOKEN", jwtToken)) // TODO: Fix like register method
//                 .build();
//         when(authenticationService.authenticate(any())).thenReturn(mockResponse);

//         mockMvc.perform(post("/api/v1/auth/authenticate")
//                 .contentType(MediaType.APPLICATION_JSON)
//                 .content(objectMapper.writeValueAsString(userDetails)))
//                 .andExpect(status().isOk())
//                 .andExpect(cookie().exists("JWT-TOKEN")); // Ensure JWT cookie is set

//         // ... Add further assertions as needed
//     }

//     @Test
//     public void testLogout() throws Exception {

//         AuthenticationResponse mockResponse = AuthenticationResponse.builder()
//                 .cookie(new Cookie("JWT-TOKEN", null)) // TODO: Fix like register method
//                 .message("Logged out successfully!")
//                 .build();

//         when(authenticationService.logout()).thenReturn(mockResponse);

//         mockMvc.perform(get("/api/v1/auth/logout")
//                 .cookie(new Cookie("JWT-TOKEN", jwtToken)) // Mock JWT cookie
//                 .header("X-XSRF-TOKEN", "testToken")) // Mock CSRF header
//                 // .andExpect(jsonPath("$.message").value("Logged out successfully!"))
//                 .andExpect(status().isOk())
//                 .andExpect(cookie().exists("JWT-TOKEN")); // Ensure JWT cookie is removed
//         // ... Add further assertions as needed
//     }

//     @Test
//     public void testVerifyEmail() throws Exception {

//         AuthenticationResponse mockResponse = AuthenticationResponse.builder()
//                 .message("Thank you for verifying your email!")
//                 .build();
//         when(authenticationService.verifyEmail(any())).thenReturn(mockResponse);

//         mockMvc.perform(post("/api/v1/auth/verify-email")
//                 .contentType(MediaType.APPLICATION_JSON)
//                 .content(objectMapper.writeValueAsString(userDetails)))
//                 .andExpect(status().isOk());
//         // ... Add further assertions as needed
//     }

//     @Test
//     public void testInitiatePasswordReset() throws Exception {
//         AuthenticationResponse mockResponse = AuthenticationResponse.builder()
//                 .message("Check your email for password reset link")
//                 .build();
//         when(authenticationService.initiatePasswordReset(any())).thenReturn(mockResponse);

//         mockMvc.perform(post("/api/v1/auth/init-password-reset")
//                 .contentType(MediaType.APPLICATION_JSON)
//                 .content(objectMapper.writeValueAsString(userDetails)))
//                 .andExpect(status().isOk());
//         // ... Add further assertions as needed
//     }

//     @Test
//     public void testResetPassword() throws Exception {
//         AuthenticationResponse mockResponse = AuthenticationResponse.builder()
//                 .message("Password reset successfull")
//                 .build();
//         when(authenticationService.resetPassword(any())).thenReturn(mockResponse);

//         mockMvc.perform(post("/api/v1/auth/reset-password")
//                 .contentType(MediaType.APPLICATION_JSON)
//                 .content(objectMapper.writeValueAsString(userDetails)))
//                 .andExpect(status().isOk());
//         // ... Add further assertions as needed
//     }

//     @Test
//     public void testUpdateUserProfile() throws Exception {
//         AuthenticationResponse mockResponse = AuthenticationResponse.builder()
//                 .message("User updated: " + userDetails.getEmail())
//                 .build();
//         when(authenticationService.updateUserProfile(any())).thenReturn(mockResponse);

//         mockMvc.perform(put("/api/v1/auth/update-user")
//                 .contentType(MediaType.APPLICATION_JSON)
//                 .content(objectMapper.writeValueAsString(userDetails)))
//                 .andExpect(status().isOk());
//         // ... Add further assertions as needed
//     }

//     @Test
//     public void testUpdateUserRole() throws Exception {
//         AuthenticationResponse mockResponse = AuthenticationResponse.builder()
//                 .message("Role updated for user: " + userDetails.getEmail())
//                 .build();
//         when(authenticationService.updateUserRole(any())).thenReturn(mockResponse);

//         mockMvc.perform(put("/api/v1/auth/update-role")
//                 .contentType(MediaType.APPLICATION_JSON)
//                 .content(objectMapper.writeValueAsString(userDetails)))
//                 .andExpect(status().isOk());
//         // ... Add further assertions as needed
//     }

// }