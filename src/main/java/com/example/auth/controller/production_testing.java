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
@RequestMapping("/api/test")
@RequiredArgsConstructor
public class production_testing {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final EmailService emailService;
    private final TokenService tokenService;
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
                .emailVerified(true)
                .enabled(true)
                .dob(request.getDob())
                .mobileNo(request.getMobile())
                .build();

        userRepository.save(user);

        return ResponseEntity.ok("User registered successfully. Please verify your email.");
    }

}
