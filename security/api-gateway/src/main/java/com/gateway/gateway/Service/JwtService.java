package com.gateway.gateway.Service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
public class JwtService {

    private final ReactiveJwtDecoder decoder;


    public JwtService(
    @Value("${jwt.jwk-set-uri}") String jwkSetUri,
    @Value("${jwt.issuer}") String issuer,
    @Value("${jwt.audience}") String audience
    ){

    NimbusReactiveJwtDecoder jwtDecoder = NimbusReactiveJwtDecoder.withJwkSetUri(jwkSetUri).build();
    var issuerValidator = JwtValidators.createDefaultWithIssuer(issuer);
    var audienceValidator = new JwtClaimValidator<java.util.Collection<String>>("aud", values -> values != null && values.contains(audience));
    jwtDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<Jwt>(issuerValidator, audienceValidator));
    this.decoder = jwtDecoder;

    }
    

    public Mono<Jwt> decode(String token) { return decoder.decode(token); }
    public Mono<String> getUsername(String token) { return decode(token).map(Jwt::getSubject); }
}

