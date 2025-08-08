package com.artimelo.configuration;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtTokenFilter jwtTokenFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable()) // отключаем CSRF для stateless API
                .cors(httpSecurityCorsConfigurer ->
                        httpSecurityCorsConfigurer.configurationSource(request ->
                                {
                                    final CorsConfiguration config = new CorsConfiguration();
                                    config.setAllowCredentials(true);
                                    config.setAllowedOriginPatterns(List.of("*"));
                                    config.addAllowedHeader("*");
                                    config.addAllowedMethod("OPTIONS");
                                    config.addAllowedMethod("HEAD");
                                    config.addAllowedMethod("GET");
                                    config.addAllowedMethod("PUT");
                                    config.addAllowedMethod("POST");
                                    config.addAllowedMethod("DELETE");
                                    config.addAllowedMethod("PATCH");
                                    return config;
                                }
                        )
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/swagger-ui/**").permitAll()  // swagger
                        .requestMatchers("/ws/**").permitAll()
                        .anyRequest().authenticated()             // всё остальное — с токеном
                )
                .addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

}

