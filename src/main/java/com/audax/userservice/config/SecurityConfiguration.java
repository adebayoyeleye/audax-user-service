package com.audax.userservice.config;

import java.io.IOException;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.annotation.PostConstruct;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {
    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors()
                .and()
                .csrf()
                .ignoringAntMatchers("/api/v1/auth/register", "/api/v1/auth/authenticate")
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .sessionAuthenticationStrategy(new NullAuthenticatedSessionStrategy())
                .and()
                // .disable()
                .authorizeHttpRequests()
                .antMatchers("/api/v1/auth/register",
                        "/api/v1/auth/authenticate",
                        "/api/v1/auth/verify-email",
                        "/api/v1/auth/init-password-reset",
                        // "/api/v1/auth/logout",
                        "/api/v1/auth/reset-password")
                .permitAll()
                .antMatchers("/api/v1/auth/update-user",
                        "/api/v1/auth/update-role")
                .authenticated()
                .anyRequest().denyAll()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        // .exceptionHandling().accessDeniedHandler(new AccessDeniedHandler() {
        // @Override
        // public void handle(HttpServletRequest request, HttpServletResponse response,
        // AccessDeniedException accessDeniedException) throws IOException,
        // ServletException {
        // // Log more details here
        // accessDeniedException.printStackTrace();
        // }
        // });

        return http.build();
    }

    // remove later
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/api/**") // Adjust the mapping pattern to match your API endpoints
                        .allowedOrigins("http://localhost:3000") // Adjust the allowed origin(s) as needed
                        .allowedMethods("GET", "POST", "PUT", "DELETE") // Adjust the allowed HTTP methods as needed
                        .allowCredentials(true) // <-- Important, allow credentials
                        .allowedHeaders("*"); // Adjust the allowed headers as needed
            }
        };
    }

}