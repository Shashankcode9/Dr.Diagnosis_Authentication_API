package com.example.auth.service;

import com.example.auth.model.User;
import com.example.auth.model.VerificationToken;
import com.example.auth.model.VerificationToken.TokenType;
import com.example.auth.repository.VerificationTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final VerificationTokenRepository tokenRepository;

    // Token valid for 24 hours
    private static final int EXPIRATION_HOURS = 24;

    public VerificationToken createToken(User user, TokenType tokenType) {
        String token = UUID.randomUUID().toString();
        String otp = generateOtp();

        VerificationToken verificationToken = VerificationToken.builder()
                .token(token)
                .user(user)
                .tokenType(tokenType)
                .otp(otp)
                .expiryDate(Instant.now().plus(EXPIRATION_HOURS, ChronoUnit.HOURS))
                .build();

        return tokenRepository.save(verificationToken);
    }
    private String generateOtp() {
        SecureRandom random = new SecureRandom();
        int otp = 100000 + random.nextInt(900000); // 6-digit OTP
        return String.valueOf(otp);
    }

    public Optional<VerificationToken> getByToken(String token) {
        return tokenRepository.findByToken(token);
    }
    public Optional<VerificationToken> getByOtp(String Otp) {
        return tokenRepository.findByOtp(Otp);
    }

    public void deleteToken(String token) {
        tokenRepository.deleteByToken(token);
    }

    public boolean isTokenExpired(VerificationToken token) {
        return token.getExpiryDate().isBefore(Instant.now());
    }
}
