package br.com.veltrix.auth.interfaces;

import static org.assertj.core.api.Assertions.assertThat;

import br.com.veltrix.auth.infrastructure.JwtKeyProvider;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class JwkSetControllerTest {
    @Test
    void exposesOnlyPublicRsaParameters() throws Exception {
        var generator=KeyPairGenerator.getInstance("RSA"); generator.initialize(2048); var pair=generator.generateKeyPair();
        var keys=new JwtKeyProvider((RSAPrivateKey)pair.getPrivate(),(RSAPublicKey)pair.getPublic(),"rotation-1");

        Map<String,Object> response=new JwkSetController(keys).jwks();
        @SuppressWarnings("unchecked") var jwk=((List<Map<String,String>>)response.get("keys")).getFirst();

        assertThat(jwk).containsEntry("kty","RSA").containsEntry("alg","RS256").containsEntry("kid","rotation-1");
        assertThat(jwk).containsKeys("n","e").doesNotContainKeys("d","p","q","privateKey");
    }
}
