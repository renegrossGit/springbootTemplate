package de.template.crud.config;

import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;

@Configuration
public class KeycloakAdapterConfig {

    public void configureGlobal(AuthenticationManagerBuilder auth) {
        KeycloakAuthenticationProvider keycloakAuthenticationProvider = new KeycloakAuthenticationProvider();
        keycloakAuthenticationProvider.setGrantedAuthoritiesMapper(new SimpleAuthorityMapper());
        auth.authenticationProvider(keycloakAuthenticationProvider);
    }
}
