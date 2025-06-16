package com.example.auth.controller;

import com.example.auth.model.User;
import com.example.auth.model.VerificationToken;
import com.example.auth.repository.UserRepository;
import com.example.auth.security.JwtUtil;
import com.example.auth.service.EmailService;
import com.example.auth.service.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/authentication")
@RequiredArgsConstructor
public class VerifyLink {
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final EmailService emailService;
    private final TokenService tokenService;

    @GetMapping("/verify-email")
    public String verifyEmail(@RequestParam String token) {
        var optionalToken = tokenService.getByToken(token);
        if (optionalToken.isEmpty()) {
            return "redirect:/error.html";
        }

        VerificationToken verificationToken = optionalToken.get();

        if (tokenService.isTokenExpired(verificationToken)) {
            return "redirect:/error.html";
        }

        User user = verificationToken.getUser();
        user.setEmailVerified(true);
        userRepository.save(user);

        tokenService.deleteToken(token);

        return "redirect:/success.html";
    }
}
