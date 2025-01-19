package de.template.crud.config;

import org.keycloak.adapters.springsecurity.KeycloakConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@KeycloakConfiguration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
/*         http
            .csrf().disable()
            .authorizeHttpRequests()
            .requestMatchers("/public/**").permitAll() // Endpunkte, die ohne Authentifizierung erreichbar sind
            .anyRequest().authenticated()
            .and()
            .oauth2Login() // Aktiviert OAuth2 Login
            .and()
            .logout().logoutSuccessUrl("/"); */ // Keycloak-Logout

        return http.build();
    }
}
