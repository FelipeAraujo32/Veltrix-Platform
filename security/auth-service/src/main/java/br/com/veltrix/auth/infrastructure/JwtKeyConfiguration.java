package br.com.veltrix.auth.infrastructure;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
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
@Profile("!test")
public class JwtKeyConfiguration {
    @Bean
    JwtKeyProvider jwtKeyProvider(@Value("${jwt.private-key-path}") String privateKeyPath,
                                  @Value("${jwt.key-id}") String keyId) throws Exception {
        String pem = Files.readString(Path.of(privateKeyPath), StandardCharsets.US_ASCII);
        String encoded = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "");
        if (encoded.isBlank()) throw new IllegalStateException("JWT private key must be a PKCS#8 PEM file");
        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPrivateKey privateKey = (RSAPrivateKey) factory.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(encoded)));
        if (!(privateKey instanceof RSAPrivateCrtKey crt)) throw new IllegalStateException("JWT private key must contain RSA CRT parameters");
        RSAPublicKey publicKey = (RSAPublicKey) factory.generatePublic(new RSAPublicKeySpec(crt.getModulus(), crt.getPublicExponent()));
        return new JwtKeyProvider(privateKey, publicKey, keyId);
    }

    @Bean
    JwtDecoder jwtDecoder(JwtKeyProvider keys,
                          @Value("${jwt.issuer}") String issuer,
                          @Value("${jwt.audience}") String audience) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(keys.publicKey()).build();
        var issuerValidator = JwtValidators.createDefaultWithIssuer(issuer);
        var audienceValidator = new JwtClaimValidator<java.util.Collection<String>>("aud", values -> values != null && values.contains(audience));
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<Jwt>(issuerValidator, audienceValidator));
        return decoder;
    }
}
