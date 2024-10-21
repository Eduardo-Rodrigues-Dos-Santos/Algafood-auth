package com.algafood.algafood_auth.core;


import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;

@Configuration
@EnableWebSecurity
public class AuthorizationServerConfig {

    @Configuration
    @EnableWebSecurity
    public class SecurityConfig {

        @Bean
        public AuthorizationServerSettings authorizationServerSettings() {
            return AuthorizationServerSettings.builder().build();
        }

        @Bean
        public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
            return new CustomToken();
        }

        @Bean
        public JWKSource<SecurityContext> jwkSource() {
            KeyPair keyPair = generateKeyPair();
            RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                    .privateKey(keyPair.getPrivate())
                    .keyID(UUID.randomUUID().toString())
                    .build();
            JWKSet jwkSet = new JWKSet(rsaKey);
            return new ImmutableJWKSet<>(jwkSet);
        }

        private KeyPair generateKeyPair() {
            KeyPair keyPair;
            try {
                var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(2048);
                keyPair = keyPairGenerator.generateKeyPair();
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
            return keyPair;
        }

        @Bean
        public CorsConfigurationSource corsConfigurationSource() {
            UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
            CorsConfiguration config = new CorsConfiguration();
            config.addAllowedHeader("*");
            config.addAllowedMethod("*");
            config.addAllowedOrigin("*");
            config.setAllowCredentials(true);
            source.registerCorsConfiguration("/**", config);
            return source;
        }

        @Bean
        public RegisteredClientRepository registeredClientRepository() {
            RegisteredClient backendClient = RegisteredClient.withId("client-id")
                    .clientId("backend-client")
                    .clientSecret(passwordEncoder().encode("321654"))
                    .scopes(strings -> strings.addAll(List.of("read", "write")))
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .build();

            RegisteredClient resourceServer = RegisteredClient.withId("resource-server-id")
                    .clientId("resource-server")
                    .clientSecret(passwordEncoder().encode("321654"))
                    .scopes(strings -> strings.addAll(List.of("read", "write")))
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .build();

            RegisteredClient webClient = RegisteredClient.withId("web-client-id")
                    .clientId("web-client")
                    .clientSecret(passwordEncoder().encode("321654"))
                    .authorizationGrantTypes(grantTypes -> grantTypes.addAll(List.of(
                            AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.REFRESH_TOKEN)))
                    .redirectUri("http://algafood-web-client")
                    .scopes(strings -> strings.addAll(List.of("write", "read")))
                    .clientSettings(ClientSettings.builder().requireProofKey(true)
                            .requireAuthorizationConsent(true).build())
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .build();

            RegisteredClient appMobile = RegisteredClient.withId("mobile")
                    .clientId("mobile-app")
                    .clientSecret(passwordEncoder().encode("321654"))
                    .redirectUris(uris -> uris.addAll(List.of("http://algafood-mobile-app",
                            "https://oauth.pstmn.io/v1/callback")))
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .clientSettings(ClientSettings.builder().requireProofKey(true).build())
                    .scopes(scopes -> scopes.addAll(List.of("READ", "WRITE")))
                    .build();

            return new InMemoryRegisteredClientRepository(List.of(backendClient, resourceServer, webClient, appMobile));
        }

        @Bean
        public PasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder();
        }
    }
}
