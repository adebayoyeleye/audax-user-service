// package com.audax.userservice.auth;

// import com.audax.userservice.auth.exceptions.DuplicateEmailException;
// import com.audax.userservice.auth.exceptions.InvalidTokenException;
// import com.audax.userservice.config.JwtService;
// import com.audax.userservice.mail.MailService;
// import com.audax.userservice.user.Role;
// import com.audax.userservice.user.User;
// import com.audax.userservice.user.UserRepository;

// import org.junit.jupiter.api.BeforeEach;
// import org.junit.jupiter.api.Test;
// import org.junit.jupiter.api.extension.ExtendWith;
// import org.mockito.InjectMocks;
// import org.mockito.Mock;
// import org.mockito.junit.jupiter.MockitoExtension;
// import org.springframework.security.authentication.AuthenticationManager;
// import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.userdetails.UsernameNotFoundException;
// import org.springframework.security.crypto.password.PasswordEncoder;

// import java.util.HashSet;
// import java.util.List;
// import java.util.Optional;

// import static org.junit.jupiter.api.Assertions.*;
// import static org.mockito.ArgumentMatchers.any;
// import static org.mockito.Mockito.*;

// @ExtendWith(MockitoExtension.class)
// public class AuthenticationServiceTest {

//     @Mock
//     private UserRepository userRepository;
//     @Mock
//     private PasswordEncoder passwordEncoder;
//     @Mock
//     private JwtService jwtService;
//     @Mock
//     private AuthenticationManager authenticationManager;
//     @Mock
//     private MailService mailService;

//     @InjectMocks
//     private AuthenticationService authenticationService;

//     private final String EMAIL = "test@email.com";
//     private final String PASSWORD = "password";
//     private final String TOKEN = "sampleToken";
//     private User sampleUser;

//     @BeforeEach
//     void setUp() {
//         sampleUser = User.builder()
//                 .email(EMAIL)
//                 .password(PASSWORD)
//                 .roles(new HashSet<>(List.of(Role.USER)))
//                 .build();
//     }

//     @Test
//     void register_withValidRequest_shouldReturnAuthenticationResponse() {
//         UserDetailsRequest request = new UserDetailsRequest();
//         request.setEmail(EMAIL);
//         request.setPassword(PASSWORD);

//         AuthenticationResponse response = authenticationService.register(request);
//         assertNotNull(response);
//         assertEquals("Check your email for validation link!", response.getMessage());
//     }

//     @Test
//     void register_withExistingEmail_shouldThrowDuplicateEmailException() {
//         UserDetailsRequest request = new UserDetailsRequest();
//         request.setEmail(EMAIL);
//         request.setPassword(PASSWORD);
//         when(userRepository.existsByEmail(request.getEmail())).thenReturn(true);

//         assertThrows(DuplicateEmailException.class, () -> authenticationService.register(request));
//     }

//     @Test
//     void verifyEmail_withValidToken_shouldReturnAuthenticationResponse() {
//         AuthenticationRequest request = new AuthenticationRequest();
//         request.setToken(TOKEN);
//         when(userRepository.findByEmailVerificationToken(request.getToken())).thenReturn(Optional.of(sampleUser));

//         AuthenticationResponse response = authenticationService.verifyEmail(request);
//         assertEquals("Thank you for verifying your email!", response.getMessage());
//     }

//     @Test
//     void verifyEmail_withInvalidToken_shouldThrowInvalidTokenException() {
//         AuthenticationRequest request = new AuthenticationRequest();
//         request.setToken(TOKEN);
//         when(userRepository.findByEmailVerificationToken(request.getToken())).thenReturn(Optional.empty());

//         assertThrows(InvalidTokenException.class, () -> authenticationService.verifyEmail(request));
//     }

//     @Test
//     void authenticate_withValidCredentials_shouldReturnAuthenticationResponse() {
//         AuthenticationRequest request = new AuthenticationRequest();
//         request.setEmail(EMAIL);
//         request.setPassword(PASSWORD);
//         sampleUser.setAccountNonLocked(true);
//         sampleUser.setAccountNonExpired(true);
//         sampleUser.setCredentialsNonExpired(true);
//         sampleUser.setEnabled(true);
//         when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(sampleUser));
//         when(authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(EMAIL, PASSWORD)))
//                 .thenReturn(null);
//         when(jwtService.generateToken(any())).thenReturn(TOKEN);

//         AuthenticationResponse response = authenticationService.authenticate(request);
//         assertEquals(TOKEN, response.getToken());
//     }

//     @Test
//     void authenticate_withInvalidCredentials_shouldThrowUsernameNotFoundException() {
//         AuthenticationRequest request = new AuthenticationRequest();
//         request.setEmail(EMAIL);
//         request.setPassword(PASSWORD);
//         when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());

//         assertThrows(UsernameNotFoundException.class,
//                 () -> authenticationService.authenticate(request));
//     }

//     // Continue for methods like initiatePasswordReset, resetPassword, etc.

//     // @Test
//     // void initiatePasswordReset_shouldWorkCorrectly() {
//     //     // TODO: Write the test
//     // }

//     // @Test
//     // void resetPassword_shouldWorkCorrectly() {
//     //     // TODO: Write the test
//     // }

//     // @Test
//     // void updateUserProfile_shouldWorkCorrectly() {
//     //     // TODO: Write the test
//     // }

//     // @Test
//     // void updateUserRole_shouldWorkCorrectly() {
//     //     // TODO: Write the test
//     // }
// }

// // @Test
// // void testAuthenticate() {

// // }

// // @Test
// // void testInitiatePasswordReset() {

// // }

// // @Test
// // void testRegister() {

// // }

// // @Test
// // void testResetPassword() {

// // }

// // @Test
// // void testUpdateUserProfile() {

// // }

// // @Test
// // void testUpdateUserRole() {

// // }

// // @Test
// // void testVerifyEmail() {

// // }