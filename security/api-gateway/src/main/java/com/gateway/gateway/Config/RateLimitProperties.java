package com.gateway.gateway.Config;

import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Rate-limiting knobs for the gateway. {@code loginLimit}/{@code loginWindow} are the strict brute-force
 * budget for {@code POST /api/v1/auth/login} per client IP; {@code globalLimit}/{@code globalWindow} are a
 * looser per-IP budget for everything else. {@code trustedProxies} are the direct peers (exact IPs or
 * CIDR blocks, e.g. {@code 10.0.0.0/8}) whose {@code X-Forwarded-For} we honour to derive the real client
 * IP — MANDATORY when the gateway sits behind an LB/ingress, otherwise every client collapses into the
 * LB's bucket. {@code exemptPaths} are Ant patterns excluded from rate-limiting entirely (e.g. payment
 * webhooks that arrive from a handful of provider IPs and carry their own fail-closed authentication);
 * module paths live ONLY in configuration, never in gateway code.
 */
@ConfigurationProperties(prefix = "veltrix.gateway.rate-limit")
public record RateLimitProperties(
        boolean enabled,
        int loginLimit,
        Duration loginWindow,
        int globalLimit,
        Duration globalWindow,
        List<String> trustedProxies,
        List<String> exemptPaths) {

    public RateLimitProperties(boolean enabled, int loginLimit, Duration loginWindow,
                               int globalLimit, Duration globalWindow,
                               List<String> trustedProxies, List<String> exemptPaths) {
        this.enabled = enabled;
        this.loginLimit = loginLimit <= 0 ? 10 : loginLimit;
        this.loginWindow = loginWindow == null ? Duration.ofMinutes(1) : loginWindow;
        this.globalLimit = globalLimit <= 0 ? 300 : globalLimit;
        this.globalWindow = globalWindow == null ? Duration.ofMinutes(1) : globalWindow;
        this.trustedProxies = trustedProxies == null ? List.of() : List.copyOf(trustedProxies);
        this.exemptPaths = exemptPaths == null ? List.of() : List.copyOf(exemptPaths);
    }
}
