package com.gateway.gateway.Filter;

import java.time.Duration;
import java.util.List;
import org.slf4j.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.*;
import org.springframework.core.Ordered;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.*;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Registry-free, convention-based entitlement gate for every business module. The service key is
 * derived from the path ({@code /api/v1/{module}/...} -> {@code MODULE}); the caller must hold the
 * {@code {MODULE}_ACCESS} permission and an active entitlement (checked against billing, cached in
 * Redis). Onboarding a new product needs only a gateway route + a billing product — no code here.
 */
@Component
public class EntitlementAuthorizationGlobalFilter implements GlobalFilter, Ordered {
    private static final Logger LOG = LoggerFactory.getLogger(EntitlementAuthorizationGlobalFilter.class);
    private final WebClient billing;
    private final ReactiveStringRedisTemplate redis;
    private final ServiceKeyResolver serviceKeys;
    private final PublicPathMatcher publicPaths;
    private final Duration ttl;

    public EntitlementAuthorizationGlobalFilter(ReactiveStringRedisTemplate redis, ServiceKeyResolver serviceKeys,
            PublicPathMatcher publicPaths, @Value("${billing.service-uri}") String uri,
            @Value("${billing.entitlement-cache-ttl:30s}") Duration ttl) {
        this.billing = WebClient.builder().baseUrl(uri).build();
        this.redis = redis;
        this.serviceKeys = serviceKeys;
        this.publicPaths = publicPaths;
        this.ttl = ttl;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();
        String serviceKey = serviceKeys.resolve(path);
        if (serviceKey == null || publicPaths.isPublic(path)) return chain.filter(exchange);
        Jwt jwt = exchange.getAttribute("veltrix.jwt");
        if (jwt == null) return reject(exchange, HttpStatus.UNAUTHORIZED);
        List<String> permissions = jwt.getClaimAsStringList("permissions");
        String requiredPermission = serviceKey + "_ACCESS";
        if (permissions == null || !permissions.contains(requiredPermission)) {
            LOG.warn("Access denied permission serviceKey={} subject={} correlationId={}", serviceKey, jwt.getSubject(), correlation(exchange));
            return reject(exchange, HttpStatus.FORBIDDEN);
        }
        String tenant = string(jwt, "tenant_id"), base = string(jwt, "base_id");
        if (tenant == null) return reject(exchange, HttpStatus.FORBIDDEN);
        String key = "entitlement:" + tenant + ":" + (base == null ? "_" : base) + ":" + serviceKey;
        return redis.opsForValue().get(key).onErrorResume(e -> Mono.empty())
                .flatMap(value -> "ALLOW".equals(value) ? chain.filter(exchange) : reject(exchange, HttpStatus.FORBIDDEN))
                .switchIfEmpty(checkAuthoritative(exchange, jwt, tenant, base, serviceKey, key)
                        .flatMap(allowed -> allowed ? chain.filter(exchange) : reject(exchange, HttpStatus.FORBIDDEN)));
    }

    private Mono<Boolean> checkAuthoritative(ServerWebExchange exchange, Jwt jwt, String tenant, String base, String serviceKey, String key) {
        return billing.post().uri("/internal/v1/entitlements/check")
                .header(HttpHeaders.AUTHORIZATION, exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
                .header(CorrelationIdGlobalFilter.HEADER, correlation(exchange))
                .contentType(MediaType.APPLICATION_JSON).bodyValue(new CheckRequest(tenant, base, serviceKey))
                .retrieve().bodyToMono(CheckResponse.class).map(CheckResponse::allowed)
                .flatMap(allowed -> redis.opsForValue().set(key, allowed ? "ALLOW" : "DENY", ttl).onErrorReturn(false).thenReturn(allowed))
                .onErrorResume(error -> {
                    LOG.error("Entitlement check failed serviceKey={} correlationId={} type={}", serviceKey, correlation(exchange), error.getClass().getSimpleName());
                    return Mono.just(false);
                });
    }

    private Mono<Void> reject(ServerWebExchange exchange, HttpStatus status) {
        exchange.getResponse().setStatusCode(status);
        return exchange.getResponse().setComplete();
    }

    private String string(Jwt jwt, String claim) {
        Object value = jwt.getClaim(claim);
        return value == null ? null : String.valueOf(value);
    }

    private String correlation(ServerWebExchange exchange) {
        return exchange.getRequest().getHeaders().getFirst(CorrelationIdGlobalFilter.HEADER);
    }

    @Override
    public int getOrder() { return -90; }

    record CheckRequest(String tenantId, String baseId, String serviceKey) {}
    record CheckResponse(boolean allowed, String status) {}
}
