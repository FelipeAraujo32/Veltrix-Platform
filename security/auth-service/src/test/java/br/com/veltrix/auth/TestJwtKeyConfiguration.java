package br.com.veltrix.auth;

import br.com.veltrix.auth.infrastructure.JwtKeyProvider;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

@Configuration
@Profile("test")
public class TestJwtKeyConfiguration {
    @Bean
    JwtKeyProvider testJwtKeyProvider() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        var pair = generator.generateKeyPair();
        return new JwtKeyProvider((RSAPrivateKey) pair.getPrivate(), (RSAPublicKey) pair.getPublic(), "test-key");
    }

    @Bean
    JwtDecoder testJwtDecoder(JwtKeyProvider keys,
                              @Value("${jwt.issuer}") String issuer,
                              @Value("${jwt.audience}") String audience) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(keys.publicKey()).build();
        var issuerValidator = JwtValidators.createDefaultWithIssuer(issuer);
        var audienceValidator = new JwtClaimValidator<java.util.Collection<String>>("aud", values -> values != null && values.contains(audience));
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<Jwt>(issuerValidator, audienceValidator));
        return decoder;
    }
}
