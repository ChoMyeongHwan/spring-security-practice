package com.example.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

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
                .oauth2Login(withDefaults());

        return http.build();
    }
}
