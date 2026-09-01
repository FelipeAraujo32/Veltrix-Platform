package com.gateway.gateway.Config;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Platform routing rules for the gateway. {@code publicPaths} are Ant patterns that bypass auth;
 * {@code platformSegments} are the {@code /api/v1/{segment}} names that are NOT entitlement-gated
 * business modules (auth, launchpad, billing, etc). Everything else under {@code /api/v1/} is treated
 * as a module and gated by convention, so onboarding a new product needs no gateway code.
 */
@ConfigurationProperties(prefix = "veltrix.gateway")
public record GatewayProperties(List<String> publicPaths, List<String> platformSegments) {
    public GatewayProperties {
        publicPaths = publicPaths == null ? List.of() : List.copyOf(publicPaths);
        platformSegments = (platformSegments == null || platformSegments.isEmpty())
                ? List.of("auth", "me", "billing", "legal", "privacy")
                : List.copyOf(platformSegments);
    }
}
