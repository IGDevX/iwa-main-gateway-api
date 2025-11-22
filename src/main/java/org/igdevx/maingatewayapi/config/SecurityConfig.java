package org.igdevx.maingatewayapi.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Mono;

import java.util.List;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    private static final String KEYCLOAK_ID_HEADER = "X-keycloak-id";

    private final SecurityProperties securityProperties;

    public SecurityConfig(SecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
    }

    @Bean
    SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
        List<String> publicPaths = securityProperties.getPublicPaths();

        http
            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            .authorizeExchange(auth -> {
                if (publicPaths != null) {
                    publicPaths.forEach(path -> auth.pathMatchers(path).permitAll());
                }
                auth.anyExchange().authenticated();
            })
            .oauth2ResourceServer(ServerHttpSecurity.OAuth2ResourceServerSpec::jwt);

        return http.build();
    }

    @Bean
    WebFilter keycloakSubjectHeaderFilter() {
        return (exchange, chain) -> exchange.getPrincipal()
            .filter(JwtAuthenticationToken.class::isInstance)
            .cast(JwtAuthenticationToken.class)
            .map(JwtAuthenticationToken::getToken)
            .map(Jwt::getSubject)
            .flatMap(sub -> {
                var mutated = exchange.mutate()
                    .request(builder -> builder.headers(headers -> headers.set(KEYCLOAK_ID_HEADER, sub)))
                    .build();
                return chain.filter(mutated);
            })
            .switchIfEmpty(Mono.defer(() -> chain.filter(exchange)));
    }
}
