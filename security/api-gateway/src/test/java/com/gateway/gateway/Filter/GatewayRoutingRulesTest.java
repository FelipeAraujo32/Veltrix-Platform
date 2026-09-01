package com.gateway.gateway.Filter;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** The generic routing rules that make the gateway module-agnostic: any new product plugs in via convention. */
class GatewayRoutingRulesTest {

    private final ServiceKeyResolver resolver = new ServiceKeyResolver(List.of("auth", "me", "billing", "legal", "privacy"));
    private final PublicPathMatcher publicPaths = new PublicPathMatcher(List.of(
            "/api/v1/auth/**", "/api/v1/billing/webhooks/**", "/.well-known/jwks.json", "/actuator/health", "/actuator/info",
            "/api/v1/ouvidoria/canais", "/api/v1/ouvidoria/manifestacoes", "/api/v1/ouvidoria/q/**",
            "/api/v1/ouvidoria/manifestacoes/*/anexos/**"));

    @Test
    void derivesServiceKeyForAnyBusinessModuleByConvention() {
        assertThat(resolver.resolve("/api/v1/finance/summary")).isEqualTo("FINANCE");
        assertThat(resolver.resolve("/api/v1/finance")).isEqualTo("FINANCE");
        assertThat(resolver.resolve("/api/v1/ouvidoria/manifestacoes")).isEqualTo("OUVIDORIA");
        // A brand-new product needs no code here — the path segment becomes the service key.
        assertThat(resolver.resolve("/api/v1/inventory/items")).isEqualTo("INVENTORY");
    }

    @Test
    void doesNotGatePlatformOrInfrastructurePaths() {
        assertThat(resolver.resolve("/api/v1/auth/login")).isNull();
        assertThat(resolver.resolve("/api/v1/me")).isNull();
        assertThat(resolver.resolve("/api/v1/me/apps")).isNull();
        assertThat(resolver.resolve("/api/v1/billing/packages")).isNull();
        assertThat(resolver.resolve("/actuator/health")).isNull();
        assertThat(resolver.resolve("/.well-known/jwks.json")).isNull();
    }

    @Test
    void recognizesConfiguredPublicPaths() {
        assertThat(publicPaths.isPublic("/api/v1/ouvidoria/canais")).isTrue();
        assertThat(publicPaths.isPublic("/api/v1/ouvidoria/manifestacoes/" + UUID.randomUUID() + "/anexos/" + UUID.randomUUID())).isTrue();
        assertThat(publicPaths.isPublic("/api/v1/auth/login")).isTrue();
    }

    @Test
    void protectedModuleEndpointsAreNotPublic() {
        assertThat(publicPaths.isPublic("/api/v1/finance/summary")).isFalse();
        assertThat(publicPaths.isPublic("/api/v1/ouvidoria/manifestacoes/" + UUID.randomUUID())).isFalse();
    }
}
