package com.gateway.gateway.Filter;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Injects the resolved real client IP as {@code X-Veltrix-Client-Ip} for downstream platform services.
 * Needed because Spring Cloud Gateway 5 with {@code trusted-proxies} enabled FILTERS the forwarded
 * {@code X-Forwarded-For} chain (post CVE-2025-41235): public client IPs never reach downstream services
 * via XFF, so per-IP controls there (e.g. the auth-service login lockout) would collapse to the gateway's
 * IP. The gateway is the one component that knows the real peer (or the LB's trusted XFF), so it publishes
 * it in a dedicated internal header.
 *
 * <p>Anti-spoof: any incoming value of this header is ALWAYS discarded and overwritten with the IP this
 * gateway resolved itself; downstream services must additionally only trust the header when the direct
 * peer is in their own trusted-proxies list. Generic platform infrastructure — carries no module knowledge.
 */
@Component
public class ClientIpHeaderGlobalFilter implements GlobalFilter, Ordered {
    public static final String HEADER = "X-Veltrix-Client-Ip";

    private final ClientIpResolver clientIp;

    public ClientIpHeaderGlobalFilter(ClientIpResolver clientIp) {
        this.clientIp = clientIp;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String ip = clientIp.resolve(exchange.getRequest());
        ServerHttpRequest request = exchange.getRequest().mutate()
                .headers(headers -> {
                    headers.remove(HEADER);
                    headers.set(HEADER, ip);
                })
                .build();
        return chain.filter(exchange.mutate().request(request).build());
    }

    @Override
    public int getOrder() {
        // After CorrelationId (-200), before rate-limit (-150) and auth (-100).
        return -160;
    }
}
