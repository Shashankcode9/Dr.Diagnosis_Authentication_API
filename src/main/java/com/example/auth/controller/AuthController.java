package com.example.auth.controller;

import com.example.auth.dto.*;
import com.example.auth.model.Role;
import com.example.auth.model.User;
import com.example.auth.model.VerificationToken;
import com.example.auth.model.VerificationToken.TokenType;
import com.example.auth.repository.UserRepository;
import com.example.auth.security.JwtUtil;
import com.example.auth.service.EmailService;
import com.example.auth.service.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;
import java.util.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final EmailService emailService;
    private final TokenService tokenService;
    @Value("${app.domain}") private String domain;

    private final String CLIENT_URL = "https://dr-diagnosis-authentication-api.onrender.com"; // change to your frontend URL

    // --- Signup with email verification email sending ---
    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody @Valid SignupRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            return ResponseEntity.badRequest().body("Email is already taken");
        }

        User user = User.builder()
                .email(request.getEmail())
                .fullName(request.getFullName())
                .password(passwordEncoder.encode(request.getPassword()))
                .roles(Set.of(Role.USER))
                .emailVerified(false)
                .build();

        userRepository.save(user);
        System.out.println(">>> New feature endpoint hit <<<");


//        // Generate email verification token
        VerificationToken verificationToken = tokenService.createToken(user, TokenType.EMAIL_VERIFICATION);
//
//        // Send verification email
        String verifyUrl = domain + "/api/authentication/verify-email?token=" + verificationToken.getToken()+ "\nOTP is -> "+verificationToken.getOtp();
        String subject = "Verify your email";
        String body = "Click the link to verify your email: " + verifyUrl;

        emailService.sendEmail(user.getEmail(), subject, body);

        return ResponseEntity.ok("User registered successfully. Please verify your email.");
    }
    @GetMapping("/verify-email")
    public ResponseEntity<?> verifyEmail(@RequestParam String token) {
        var optionalToken = tokenService.getByToken(token);
        if (optionalToken.isEmpty()) {
            return ResponseEntity.ok("fail");
        }

        VerificationToken verificationToken = optionalToken.get();

        if (tokenService.isTokenExpired(verificationToken)) {
            return ResponseEntity.ok("fail 2");
        }

        User user = verificationToken.getUser();
        user.setEmailVerified(true);
        userRepository.save(user);

        tokenService.deleteToken(token);

        return ResponseEntity.ok("pass");
    }

    // --- Login ---
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody @Valid LoginRequest request) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
            );

            var user = userRepository.findByEmail(request.getEmail()).orElseThrow();

            if (!user.isEmailVerified()) {
                return ResponseEntity.status(403).body("Email not verified");
            }

            String accessToken = jwtUtil.generateAccessToken(request.getEmail());
            String refreshToken = jwtUtil.generateRefreshToken(request.getEmail());

            return ResponseEntity.ok(new AuthResponse(accessToken, refreshToken));

        } catch (BadCredentialsException ex) {
            return ResponseEntity.status(401).body("Invalid email or password");
        }
    }

    // --- Verify Email ---

    @PostMapping("/verify-otp")
    public ResponseEntity<?> verifyByOtp(@RequestBody otprequest otprequest) {
        var token = tokenService.getByOtp(otprequest.getOtp()).get().getToken();
        var optionalToken = tokenService.getByToken(token);
        if (optionalToken.isEmpty()) {
            return ResponseEntity.badRequest().body("Invalid token");
        }

        VerificationToken verificationToken = optionalToken.get();

        if (tokenService.isTokenExpired(verificationToken)) {
            return ResponseEntity.badRequest().body("Token expired");
        }

        User user = verificationToken.getUser();
        user.setEmailVerified(true);
        userRepository.save(user);

        tokenService.deleteToken(token);

        return ResponseEntity.ok("Email verified successfully");
    }

    // --- Forgot Password ---
    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody @Valid EmailRequest request) {
        var userOpt = userRepository.findByEmail(request.getEmail());
        if (userOpt.isEmpty()) {
            // Do not reveal email existence
            return ResponseEntity.ok("Password reset email sent if email exists");
        }

        User user = userOpt.get();
        VerificationToken resetToken = tokenService.createToken(user, TokenType.PASSWORD_RESET);

        String resetUrl = CLIENT_URL + "/reset-password?token=" + resetToken.getToken();
        String subject = "Reset your password";
        String body = "Click the link to reset your password: " + resetUrl;

        emailService.sendEmail(user.getEmail(), subject, body);

        return ResponseEntity.ok("Password reset email sent if email exists");
    }

    // --- Reset Password ---
    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody @Valid ResetPasswordRequest request) {
        var optionalToken = tokenService.getByToken(request.getToken());
        if (optionalToken.isEmpty()) {
            return ResponseEntity.badRequest().body("Invalid token");
        }

        VerificationToken verificationToken = optionalToken.get();
        if (tokenService.isTokenExpired(verificationToken)) {
            return ResponseEntity.badRequest().body("Token expired");
        }

        if (verificationToken.getTokenType() != TokenType.PASSWORD_RESET) {
            return ResponseEntity.badRequest().body("Invalid token type");
        }

        User user = verificationToken.getUser();
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);

        tokenService.deleteToken(request.getToken());

        return ResponseEntity.ok("Password reset successful");
    }

    // --- Refresh Token ---
    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestParam String refreshToken) {
        if (!jwtUtil.validateToken(refreshToken)) {
            return ResponseEntity.status(401).body("Invalid refresh token");
        }
        String email = jwtUtil.getEmailFromToken(refreshToken);
        String newAccessToken = jwtUtil.generateAccessToken(email);
        String newRefreshToken = jwtUtil.generateRefreshToken(email);
        return ResponseEntity.ok(new AuthResponse(newAccessToken, newRefreshToken));
    }
}
