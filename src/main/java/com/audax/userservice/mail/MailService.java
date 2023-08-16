package com.audax.userservice.mail;

public interface MailService {
    void sendPasswordResetEmail(String email, String resetToken);

    void sendVerificationEmail(String email, String emailVerificationToken);
}
