package com.gateway.gateway.Filter;

import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Maps a request path to a module service key by convention: {@code /api/v1/{module}/...} becomes
 * {@code MODULE}. Platform/infra segments (auth, me, billing, ...) return {@code null} so they are
 * not entitlement-gated. No per-module code or registry lookup is required on the hot path.
 */
public class ServiceKeyResolver {
    private static final String API_PREFIX = "/api/v1/";
    private final Set<String> platformSegments;

    public ServiceKeyResolver(List<String> platformSegments) {
        this.platformSegments = Set.copyOf(platformSegments);
    }

    public String resolve(String path) {
        if (path == null || !path.startsWith(API_PREFIX)) return null;
        String rest = path.substring(API_PREFIX.length());
        int slash = rest.indexOf('/');
        String segment = slash < 0 ? rest : rest.substring(0, slash);
        if (segment.isEmpty() || platformSegments.contains(segment)) return null;
        return segment.toUpperCase(Locale.ROOT);
    }
}
