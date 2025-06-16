package com.example.auth.controller;

import com.example.auth.dto.DeleteRequest;
import com.example.auth.dto.SignupRequest;
import com.example.auth.model.Role;
import com.example.auth.model.User;
import com.example.auth.model.VerificationToken;
import com.example.auth.repository.UserRepository;
import com.example.auth.security.JwtUtil;
import com.example.auth.service.CustomUserDetailsService;
import com.example.auth.service.EmailService;
import com.example.auth.service.TokenService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;
import java.util.Set;

@RestController
@RequestMapping("/api/delete")
@RequiredArgsConstructor
public class DangerZone {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final EmailService emailService;
    private final TokenService tokenService;
    private final CustomUserDetailsService userService;
    private final String CLIENT_URL = "https://dr-diagnosis-authentication-api.onrender.com";
    @DeleteMapping()
    public ResponseEntity<?> delete(@RequestBody DeleteRequest request) {
        var User = userService.getByEmail(request.getEmail());

        if (!userRepository.existsByEmail(request.getEmail())) {
            return ResponseEntity.badRequest().body("Email is not taken");
        }
        userRepository.deleteById(User.get().getId());

        return ResponseEntity.ok("User Deleted successfully.");
    }

}
