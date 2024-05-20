package com.example.buysell.configurations;

import com.example.buysell.services.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    private final CustomUserDetailsService customUserDetailsService;


    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        logger.debug("Configuring security filter chain");
        http
                .authorizeRequests(auth -> {
                    logger.debug("Configuring authorized requests");
                    auth.requestMatchers("/", "/product/**", "/images/**", "/registration", "/user/**").permitAll()
                            .anyRequest().authenticated();
                })
                .formLogin(form -> {
                    logger.debug("Configuring form login");
                    form.loginPage("/login")
                            .defaultSuccessUrl("/")
                            .permitAll();
                })
                .logout(logout -> {
                    logger.debug("Configuring logout");
                    logout.permitAll();
                });
        return http.build();
    }

    @Bean
    @Primary
    public AuthenticationManagerBuilder configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(customUserDetailsService)
                .passwordEncoder(passwordEncoder());
        return auth;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(8);
    }
}
