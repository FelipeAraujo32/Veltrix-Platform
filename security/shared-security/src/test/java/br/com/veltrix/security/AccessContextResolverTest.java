package br.com.veltrix.security;

import static org.assertj.core.api.Assertions.assertThat;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

class AccessContextResolverTest {
    @Test void resolvesCommercialAndOperationalClaims() {
        Jwt jwt = Jwt.withTokenValue("token").header("alg", "none").subject("user-1")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60))
                .claim("tenant_id", "tenant-1").claim("base_id", "base-1")
                .claim("permissions", List.of("OUVIDORIA_ACCESS")).claim("access_version", 7).build();
        var context = AccessContextResolver.resolve(new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("OUVIDORIA_ACCESS")))).orElseThrow();
        assertThat(context.tenantId()).isEqualTo("tenant-1");
        assertThat(context.baseId()).isEqualTo("base-1");
        assertThat(context.permissions()).containsExactly("OUVIDORIA_ACCESS");
        assertThat(context.accessVersion()).isEqualTo(7);
    }
}
