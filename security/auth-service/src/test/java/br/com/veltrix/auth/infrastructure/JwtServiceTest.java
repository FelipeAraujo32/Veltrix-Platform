package br.com.veltrix.auth.infrastructure;

import static org.assertj.core.api.Assertions.assertThat;

import br.com.veltrix.auth.domain.User;
import br.com.veltrix.auth.domain.UserStatus;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

class JwtServiceTest {
    @Test
    void emitsExplicitContextScopes() throws Exception {
        var generator=KeyPairGenerator.getInstance("RSA"); generator.initialize(2048); var pair=generator.generateKeyPair();
        JwtKeyProvider keys=new JwtKeyProvider((RSAPrivateKey)pair.getPrivate(),(RSAPublicKey)pair.getPublic(),"test-key");
        JwtService service=new JwtService(keys,"veltrix-auth","veltrix-services",300);
        User user=new User("operator@example.test","hash","Operador",UserStatus.ACTIVE);
        ReflectionTestUtils.setField(user,"id",42L);
        user.addContextScope("PREFEITURA_CAMPINAS");

        String token=service.create(user);
        var parsed=io.jsonwebtoken.Jwts.parser().verifyWith(keys.publicKey()).requireIssuer("veltrix-auth").requireAudience("veltrix-services").build().parseSignedClaims(token);
        var claims=parsed.getPayload();

        assertThat(claims.get("contexts",java.util.List.class)).containsExactly("PREFEITURA_CAMPINAS");
        assertThat(parsed.getHeader().getAlgorithm()).isEqualTo("RS256");
        assertThat(parsed.getHeader().getKeyId()).isEqualTo("test-key");
    }
}
