package com.test.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.util.UUID;

@Configuration
public class ClientConfig {

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        Object AuthorizationGrantType;
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client-id")
                .clientSecret("{noop}client-secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .redirectUri("http://localhost:8080/login/oauth2/code/custom")
                .scope("read")
                .scope("write")
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }
}
