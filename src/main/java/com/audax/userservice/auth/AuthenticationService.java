package com.audax.userservice.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.audax.userservice.auth.exceptions.AccountNotEnabled;
import com.audax.userservice.auth.exceptions.DuplicateEmailException;
import com.audax.userservice.auth.exceptions.InvalidTokenException;
import com.audax.userservice.auth.exceptions.UnauthorizedException;
import com.audax.userservice.config.JwtService;
import com.audax.userservice.mail.MailService;
import com.audax.userservice.user.Role;
import com.audax.userservice.user.User;
import com.audax.userservice.user.UserRepository;

import lombok.RequiredArgsConstructor;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

        private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationService.class);

        private final UserRepository userRepository;
        private final PasswordEncoder passwordEncoder;
        private final JwtService jwtService;
        private final AuthenticationManager authenticationManager;
        private final MailService mailService; // Assuming you have a service to handle sending emails

        public AuthenticationResponse register(UserDetailsRequest request) {
                if (userRepository.existsByEmail(request.getEmail())) {
                        throw new DuplicateEmailException("Email already in use: " + request.getEmail());
                }

                var user = User.builder()
                                .firstname(request.getFirstname())
                                .lastname(request.getLastname())
                                .email(request.getEmail())
                                .password(passwordEncoder.encode(request.getPassword()))
                                .roles(new HashSet<>(List.of(Role.USER)))
                                .isAccountNonLocked(true)
                                .isAccountNonExpired(true)
                                .isCredentialsNonExpired(true)
                                .isEnabled(false)
                                .emailVerificationToken(UUID.randomUUID().toString())
                                .createdAt(LocalDateTime.now())
                                .build();

                userRepository.save(user);
                mailService.sendVerificationEmail(user.getEmail(), user.getEmailVerificationToken());

                LOGGER.info("New user registered: {}", user.getEmail());

                String jwtToken = jwtService.generateToken(user);

                return AuthenticationResponse.builder()
                                .token(jwtToken)
                                .message("Check your email for validation link!")
                                .build();
        }

        public AuthenticationResponse verifyEmail(AuthenticationRequest request) {
                User user = userRepository.findByEmailVerificationToken(request.getToken())
                                .orElseThrow(() -> new InvalidTokenException(
                                                "Invalid email verification token: " + request.getToken()));

                user.setEmailVerificationToken(null);
                user.setEnabled(true);

                userRepository.save(user);
                return AuthenticationResponse.builder()
                                .message("Thank you for verifying your email!")
                                .build();
        }

        public AuthenticationResponse authenticate(AuthenticationRequest request) {
                User user = userRepository.findByEmail(request.getEmail())
                                .orElseThrow(() -> new UsernameNotFoundException(
                                                "User not found with email: " + request.getEmail()));

                if (!user.isAccountNonLocked()) {
                        throw new UnauthorizedException("The account is locked: " + user.getEmail());
                }

                if (!user.isAccountNonExpired() || !user.isCredentialsNonExpired()) {
                        throw new UnauthorizedException("The account or credentials have expired: " + user.getEmail());
                }

                if (!user.isEnabled()) {
                        throw new AccountNotEnabled("Account not enabled: " + user.getEmail());
                }

                authenticationManager.authenticate(
                                new UsernamePasswordAuthenticationToken(
                                                request.getEmail(),
                                                request.getPassword()));

                String jwtToken = jwtService.generateToken(user);

                return AuthenticationResponse.builder()
                                .token(jwtToken)
                                .build();
        }

        public AuthenticationResponse initiatePasswordReset(AuthenticationRequest request) {
                User user = userRepository.findByEmail(request.getEmail())
                                .orElseThrow(() -> new UsernameNotFoundException(
                                                "User not found with email: " + request.getEmail()));

                String resetToken = UUID.randomUUID().toString();
                user.setPasswordResetToken(resetToken);
                user.setPasswordResetExpiresAt(LocalDateTime.now().plusHours(2)); // Token expires in 2 hours

                userRepository.save(user);

                mailService.sendPasswordResetEmail(user.getEmail(), resetToken);
                LOGGER.info("Password reset token sent for user: {}", user.getEmail());

                return AuthenticationResponse.builder()
                                .message("Check your email for password reset link")
                                .build();
        }

        public AuthenticationResponse resetPassword(AuthenticationRequest request) {
                User user = userRepository.findByPasswordResetToken(request.getToken())
                                .orElseThrow(() -> new InvalidTokenException("Invalid password reset token: " + request.getToken()));

                if (user.getPasswordResetExpiresAt().isBefore(LocalDateTime.now())) {
                        throw new InvalidTokenException("The password reset token has expired: " + user.getEmail());
                }

                user.setPassword(passwordEncoder.encode(request.getPassword()));
                user.setPasswordResetToken(null);
                user.setPasswordResetExpiresAt(null);
                user.setUpdatedAt(LocalDateTime.now());

                userRepository.save(user);

                LOGGER.info("Successful password reset for user: {}", user.getEmail());
                return AuthenticationResponse.builder()
                                .message("Password reset successfull")
                                .build();
        }

        public AuthenticationResponse updateUserProfile(AuthenticationRequest request) {
                User user = userRepository.findByEmail(request.getEmail())
                                .orElseThrow(() -> new UsernameNotFoundException(
                                                "User not found with email: " + request.getEmail()));

                user.setFirstname(request.getUserDetailsRequest().getFirstname());
                user.setLastname(request.getUserDetailsRequest().getLastname());
                user.setEmail(request.getUserDetailsRequest().getEmail());
                user.setUpdatedAt(LocalDateTime.now());

                if (request.getUserDetailsRequest().getPassword() != null && !request.getUserDetailsRequest().getPassword().isEmpty()) {
                        user.setPassword(passwordEncoder.encode(request.getUserDetailsRequest().getPassword()));
                }

                userRepository.save(user);

                LOGGER.info("User updated: {}", user.getEmail());
return AuthenticationResponse.builder()
                                .message("User updated: " + user.getEmail())
                                .build();        }

        public AuthenticationResponse updateUserRole(AuthenticationRequest request) {
                User adminUser = userRepository.findByEmail(request.getAdminEmail())
                                .orElseThrow(() -> new UsernameNotFoundException(
                                                "Admin user not found: " + request.getAdminEmail()));

                if (!adminUser.getRoles().contains(Role.ADMIN)) {
                        throw new UnauthorizedException(
                                        "Insufficient permissions to update user role: " + request.getAdminEmail() + " - "
                                                        + adminUser.getRoles());
                }

                User user = userRepository.findByEmail(request.getEmail())
                                .orElseThrow(() -> new UsernameNotFoundException(
                                                "User not found with email: " + request.getEmail()));

                user.setRoles(new HashSet<>(List.of(request.getRole())));
                user.setUpdatedAt(LocalDateTime.now());
                userRepository.save(user);

                LOGGER.info("Role updated for user: {}", user.getEmail());
return AuthenticationResponse.builder()
                                .message("Role updated for user: " + user.getEmail())
                                .build();        }
}
