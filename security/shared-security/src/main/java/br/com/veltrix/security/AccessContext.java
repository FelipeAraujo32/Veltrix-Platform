package br.com.veltrix.security;

import java.util.Set;

public record AccessContext(String userId, String tenantId, String baseId, Set<String> permissions,
                            long accessVersion) {
    public AccessContext {
        permissions = permissions == null ? Set.of() : Set.copyOf(permissions);
    }
}
