package com.gateway.gateway.Filter;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.gateway.gateway.Service.JwtService;

import reactor.core.publisher.Mono;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component
public class JwtAuthenticationGlobalFilter implements GlobalFilter, Ordered {

    private static final Logger LOG = LoggerFactory.getLogger(JwtAuthenticationGlobalFilter.class);

    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtService jwtService;
    private final PublicPathMatcher publicPaths;

    public JwtAuthenticationGlobalFilter(JwtService jwtService, PublicPathMatcher publicPaths) {
        this.jwtService = jwtService;
        this.publicPaths = publicPaths;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();
        String correlationId = exchange.getRequest().getHeaders().getFirst("X-Correlation-Id");

        if (publicPaths.isPublic(path)) {
            return chain.filter(exchange);
        }

        String authorization = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authorization == null || !authorization.startsWith(BEARER_PREFIX)) {
            LOG.warn("JWT rejeitado: Authorization ausente ou inválido, path={}, correlationId={}", path, correlationId);
            return unauthorized(exchange);
        }

        String token = authorization.substring(BEARER_PREFIX.length());

        return jwtService.decode(token)
                .flatMap(jwt -> {
                    LOG.info("JWT validado no gateway, subject={}, path={}, correlationId={}", jwt.getSubject(), path, correlationId);
                    exchange.getAttributes().put("veltrix.jwt", jwt);
                    return chain.filter(exchange);
                })
                .onErrorResume(exception -> {
                    LOG.warn("JWT rejeitado: tipo={}, motivo={}, path={}, correlationId={}", exception.getClass().getSimpleName(), exception.getMessage(), path, correlationId);
                    return unauthorized(exchange);
                });
    }

    @Override
    public int getOrder() {
        return -100;
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }
}
