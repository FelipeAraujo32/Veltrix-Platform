package com.gateway.gateway.Filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class SecurityHeadersGlobalFilter implements GlobalFilter, Ordered {
    private static final Logger LOG = LoggerFactory.getLogger(SecurityHeadersGlobalFilter.class);
    /** TLS terminates at the external LB, but the HSTS browser directive is emitted at our edge. */
    public static final String DEFAULT_HSTS_VALUE = "max-age=31536000; includeSubDomains";

    private final boolean hstsEnabled;
    private final String hstsValue;

    public SecurityHeadersGlobalFilter(
            @Value("${veltrix.gateway.hsts.enabled:true}") boolean hstsEnabled,
            @Value("${veltrix.gateway.hsts.value:" + DEFAULT_HSTS_VALUE + "}") String hstsValue) {
        this.hstsEnabled = hstsEnabled;
        this.hstsValue = hstsValue;
        if (!hstsEnabled) {
            LOG.warn("Strict-Transport-Security is DISABLED (veltrix.gateway.hsts.enabled=false) — acceptable for local plain-HTTP development only, never in production.");
        }
    }

    @Override public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        var headers=exchange.getResponse().getHeaders();
        if (hstsEnabled) headers.set("Strict-Transport-Security", hstsValue);
        headers.set("Content-Security-Policy","default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'");
        headers.set("Permissions-Policy","camera=(), microphone=(), geolocation=(), payment=()");
        headers.set("X-Frame-Options","DENY");
        headers.set("Cross-Origin-Opener-Policy","same-origin");
        return chain.filter(exchange);
    }
    @Override public int getOrder(){return -200;}
}
