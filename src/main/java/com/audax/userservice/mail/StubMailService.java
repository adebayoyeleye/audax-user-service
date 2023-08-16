package com.audax.userservice.mail;

import org.springframework.stereotype.Service;

@Service
public class StubMailService implements MailService {

    @Override
    public void sendPasswordResetEmail(String email, String resetToken) {
        // TODO: Implement communication with the other microservice.
        // This is a stub implementation for testing purposes.
        System.out.println("Password reset email sent to " + email + " with reset token: " + resetToken);
    }

    @Override
    public void sendVerificationEmail(String email, String emailVerificationToken) {
        // TODO Auto-generated method stub
        System.out.println("Verification email sent to " + email);
    }
}
