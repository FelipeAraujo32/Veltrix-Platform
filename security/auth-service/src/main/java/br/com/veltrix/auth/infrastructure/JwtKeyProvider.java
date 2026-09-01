package br.com.veltrix.auth.infrastructure;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public record JwtKeyProvider(RSAPrivateKey privateKey, RSAPublicKey publicKey, String keyId) {
    public JwtKeyProvider {
        if (privateKey == null || publicKey == null) throw new IllegalArgumentException("RSA key pair is required");
        if (publicKey.getModulus().bitLength() < 2048) throw new IllegalArgumentException("JWT RSA key must have at least 2048 bits");
        if (keyId == null || keyId.isBlank()) throw new IllegalArgumentException("JWT key id is required");
    }
}
