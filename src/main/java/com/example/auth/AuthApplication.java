package com.example.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AuthApplication {
    //System.out.println("webAllowOthers: " + System.getProperty("webAllowOthers"));

    public static void main(String[] args) {
        SpringApplication.run(AuthApplication.class, args);
    }
}