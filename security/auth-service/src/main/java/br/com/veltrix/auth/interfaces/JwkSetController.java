package br.com.veltrix.auth.interfaces;

import br.com.veltrix.auth.infrastructure.JwtKeyProvider;
import java.math.BigInteger;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwkSetController {
    private final JwtKeyProvider keys;

    public JwkSetController(JwtKeyProvider keys) { this.keys = keys; }

    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> jwks() {
        return Map.of("keys", List.of(Map.of(
                "kty", "RSA", "use", "sig", "alg", "RS256", "kid", keys.keyId(),
                "n", unsigned(keys.publicKey().getModulus()),
                "e", unsigned(keys.publicKey().getPublicExponent()))));
    }

    private String unsigned(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) bytes = java.util.Arrays.copyOfRange(bytes, 1, bytes.length);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
