// package com.audax.userservice.config;

// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.context.annotation.Profile;
// import org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
// import org.springframework.security.web.SecurityFilterChain;

// @Configuration
// @EnableWebSecurity
// @Profile("test")
// public class TestSecurityConfiguration {

//     @Bean
//     public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//         http
//             .csrf().disable() // This disables CSRF protection
//             .authorizeRequests()
//                 .anyRequest().permitAll();  // Permit all requests for simplicity in testing
        
//         return http.build();
//     }
// }
