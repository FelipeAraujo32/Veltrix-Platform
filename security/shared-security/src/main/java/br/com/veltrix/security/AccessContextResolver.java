package br.com.veltrix.security;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;

public final class AccessContextResolver {
    private AccessContextResolver() {}

    public static Optional<AccessContext> resolve(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated() || !(authentication.getPrincipal() instanceof Jwt jwt)) {
            return Optional.empty();
        }
        String tenantId = claim(jwt, "tenant_id");
        String baseId = claim(jwt, "base_id");
        if (baseId == null) {
            List<String> contexts = jwt.getClaimAsStringList("contexts");
            if (contexts != null && contexts.size() == 1 && !"*".equals(contexts.getFirst())) baseId = contexts.getFirst();
        }
        var permissions = new HashSet<String>();
        List<String> values = jwt.getClaimAsStringList("permissions");
        if (values != null) permissions.addAll(values);
        Number accessVersion = jwt.getClaim("access_version");
        return Optional.of(new AccessContext(jwt.getSubject(), tenantId, baseId, permissions,
                accessVersion == null ? 0 : accessVersion.longValue()));
    }

    private static String claim(Jwt jwt, String name) {
        Object value = jwt.getClaim(name);
        return value == null ? null : String.valueOf(value);
    }
}
