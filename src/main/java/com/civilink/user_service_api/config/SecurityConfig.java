package com.civilink.user_service_api.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        http.csrf(AbstractHttpConfigurer::disable);
        http.authorizeHttpRequests(authorize->{
           authorize.requestMatchers(HttpMethod.POST,"/api/v1/users/create").permitAll()
                   .requestMatchers(HttpMethod.POST,"/api/v1/users/login").permitAll()
                   .requestMatchers(HttpMethod.POST,"/api/v1/users/verify").permitAll()
                   .anyRequest()
                   .authenticated();
        });

        http.oauth2ResourceServer(t->t.jwt((Customizer.withDefaults())));

        http.sessionManagement(t->t.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http.logout(logout -> logout
                .logoutUrl("/logout") // Local logout endpoint
                .addLogoutHandler(keycloakLogoutHandler()) // Custom Keycloak logout handler
                .logoutSuccessHandler(keycloakLogoutSuccessHandler()) // Redirect to Keycloak after logout
        );

        return http.build();
    }

    @Bean
    public DefaultMethodSecurityExpressionHandler msecurity(){
        DefaultMethodSecurityExpressionHandler defaultMethodSecurityExpressionHandler = new DefaultMethodSecurityExpressionHandler();
        defaultMethodSecurityExpressionHandler.setDefaultRolePrefix("");
        return defaultMethodSecurityExpressionHandler;
    }

    @Bean
    public LogoutHandler keycloakLogoutHandler() {
        return (request, response, authentication) -> {
            // You can add logic to revoke tokens if needed.
        };
    }

    @Bean
    public LogoutSuccessHandler keycloakLogoutSuccessHandler() {
        return (request, response, authentication) -> {
            String keycloakLogoutUrl = "http://localhost:8080/realms/civilink/protocol/openid-connect/logout";
            response.sendRedirect(keycloakLogoutUrl);
        };
    }




}
