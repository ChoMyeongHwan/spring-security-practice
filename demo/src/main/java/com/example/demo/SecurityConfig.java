package com.example.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests
                                // 모든 사용자에게 허용
                                .antMatchers("/", "/error", "/webjars/**").permitAll()
                                // 그 외 모든 요청은 인증된 사용자에게 허용
                                .anyRequest().authenticated()
                )
                // OAuth2 로그인을 사용하고, 기본 구성을 적용
                .oauth2Login(withDefaults())
                .logout(l -> l
                        .logoutSuccessUrl("/").permitAll() // 로그아웃 성공 시 리다이렉트될 경로 설정
                )
                .csrf(c -> c
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()) // CSRF 보호를 활성화하고 HttpOnly를 비활성화
                );

        return http.build();
    }
}

