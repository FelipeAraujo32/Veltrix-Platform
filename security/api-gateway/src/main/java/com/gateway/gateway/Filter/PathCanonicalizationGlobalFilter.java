package com.gateway.gateway.Filter;

import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Edge guard that rejects requests whose RAW path is not canonical BEFORE any routing, auth, rate-limit
 * or entitlement decision runs. The other filters (Jwt public-paths, RateLimit exempt-paths, Entitlement
 * service-key derivation) all make security decisions on the request path; if the gateway evaluated a
 * non-canonical path (e.g. {@code /api/v1/billing/webhooks/../foo} or percent-encoded {@code %2e%2e}) it
 * could reach a different downstream target than the one it authorized. The downstream StrictHttpFirewall
 * would still block {@code ../}, so this is defense-in-depth (W1.5: an exempt-path with {@code ../} slipping
 * the rate-limit and routing to billing) — the gateway must never take a security decision on a
 * non-canonical path.
 *
 * <p>Policy is REJECT, not normalize-and-continue: normalizing here would risk the gateway evaluating one
 * path while Spring Cloud Gateway forwards another. Purely a generic path rule — carries no module
 * knowledge. Rejections respond {@code 400} with the platform standard error body and never echo the
 * offending path (avoids reflection).
 */
@Component
public class PathCanonicalizationGlobalFilter implements GlobalFilter, Ordered {

    private static final Logger LOG = LoggerFactory.getLogger(PathCanonicalizationGlobalFilter.class);

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String rawPath = exchange.getRequest().getURI().getRawPath();
        if (isNonCanonical(rawPath)) {
            LOG.warn("Non-canonical path rejected at gateway edge correlationId={}", correlation(exchange));
            return badRequest(exchange);
        }
        return chain.filter(exchange);
    }

    /**
     * True when the raw (un-decoded) path contains any construct that could make the gateway's routing/auth
     * decision diverge from what is forwarded downstream: dot-segments ({@code ..}), empty segments
     * ({@code //}), percent-encoded dots or slashes/backslashes ({@code %2e}, {@code %2f}, {@code %5c}),
     * a literal backslash, or control characters.
     */
    boolean isNonCanonical(String rawPath) {
        if (rawPath == null || rawPath.isEmpty()) return false;
        if (rawPath.contains("..")) return true;      // dot-segment (raw or with encoded neighbours)
        if (rawPath.contains("//")) return true;      // empty path segment
        if (rawPath.indexOf('\\') >= 0) return true;  // literal backslash
        String lower = rawPath.toLowerCase();
        if (lower.contains("%2e")) return true;        // encoded dot
        if (lower.contains("%2f")) return true;        // encoded forward slash
        if (lower.contains("%5c")) return true;        // encoded backslash
        for (int i = 0; i < rawPath.length(); i++) {
            char c = rawPath.charAt(i);
            if (c < 0x20 || c == 0x7f) return true;    // control characters (incl. CR, LF, NUL, DEL)
        }
        return false;
    }

    private Mono<Void> badRequest(ServerWebExchange exchange) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.BAD_REQUEST);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        String correlationId = correlation(exchange);
        if (correlationId == null || correlationId.isBlank()) correlationId = UUID.randomUUID().toString();
        // This filter runs before CorrelationIdGlobalFilter, so echo the id on the response ourselves.
        response.getHeaders().set(CorrelationIdGlobalFilter.HEADER, correlationId);
        String body = "{\"error\":\"INVALID_REQUEST\",\"message\":\"Requisição inválida.\",\"correlationId\":\""
                + correlationId + "\",\"timestamp\":\"" + java.time.Instant.now() + "\"}";
        DataBuffer buffer = response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }

    private String correlation(ServerWebExchange exchange) {
        return exchange.getRequest().getHeaders().getFirst(CorrelationIdGlobalFilter.HEADER);
    }

    @Override
    public int getOrder() {
        // Absolute edge: before SecurityHeaders/Correlation (-200) and everything downstream, so no filter
        // ever takes a routing/auth/rate-limit/entitlement decision on a non-canonical path.
        return Ordered.HIGHEST_PRECEDENCE;
    }
}
