package com.gateway.gateway.Filter;

import com.gateway.gateway.Config.RateLimitProperties;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Redis-backed, fixed-window rate limiter applied as a {@link GlobalFilter} (the gateway wires all
 * cross-cutting concerns as global filters and {@code SecurityConfig} permits every exchange, so a
 * per-route {@code RequestRateLimiter} would not fit the current architecture). The login endpoint gets
 * a strict per-IP budget to close brute-force (L4); every other request gets a looser global per-IP
 * budget. Configured {@code exempt-paths} (e.g. payment webhooks arriving from a handful of provider IPs
 * with their own fail-closed authentication downstream) bypass the limiter entirely — those paths live
 * ONLY in configuration, keeping this filter module-agnostic. Exceeding a budget responds {@code 429}
 * with the platform standard error body. The counter is an atomic INCR+EXPIRE Lua script, so a failure
 * between the two commands can never leave a TTL-less key. Fail-open on Redis errors so an outage cannot
 * take the whole platform offline.
 */
@Component
public class RateLimitGlobalFilter implements GlobalFilter, Ordered {
    private static final Logger LOG = LoggerFactory.getLogger(RateLimitGlobalFilter.class);
    private static final String LOGIN_PATH = "/api/v1/auth/login";
    /** Atomic fixed-window counter: INCR and, on first hit only, EXPIRE — single round-trip. */
    private static final RedisScript<Long> INCREMENT_SCRIPT = RedisScript.of(
            "local c = redis.call('INCR', KEYS[1]) if c == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end return c",
            Long.class);

    private final ReactiveStringRedisTemplate redis;
    private final ClientIpResolver clientIp;
    private final RateLimitProperties props;
    private final PublicPathMatcher exemptPaths;

    public RateLimitGlobalFilter(ReactiveStringRedisTemplate redis, ClientIpResolver clientIp, RateLimitProperties props) {
        this.redis = redis;
        this.clientIp = clientIp;
        this.props = props;
        this.exemptPaths = new PublicPathMatcher(props.exemptPaths());
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        if (!props.enabled()) return chain.filter(exchange);
        ServerHttpRequest request = exchange.getRequest();
        if (exemptPaths.isPublic(request.getURI().getPath())) return chain.filter(exchange);
        String ip = clientIp.resolve(request);

        boolean isLogin = HttpMethod.POST.equals(request.getMethod())
                && LOGIN_PATH.equals(request.getURI().getPath());

        String bucket = isLogin ? "login" : "global";
        int limit = isLogin ? props.loginLimit() : props.globalLimit();
        Duration window = isLogin ? props.loginWindow() : props.globalWindow();
        String key = "ratelimit:" + bucket + ":" + ip;

        return count(key, window)
                .flatMap(current -> {
                    if (current > limit) {
                        LOG.warn("Rate limit exceeded bucket={} ip={} count={} limit={} correlationId={}",
                                bucket, ip, current, limit, correlation(exchange));
                        return tooManyRequests(exchange, window);
                    }
                    return chain.filter(exchange);
                })
                // Fail-open: a Redis outage must not lock everyone out of the platform.
                .onErrorResume(error -> {
                    LOG.error("Rate limiter unavailable, allowing request bucket={} ip={} type={}",
                            bucket, ip, error.getClass().getSimpleName());
                    return chain.filter(exchange);
                });
    }

    private Mono<Long> count(String key, Duration window) {
        return redis.execute(INCREMENT_SCRIPT, List.of(key), List.of(String.valueOf(window.toSeconds()))).next();
    }

    private Mono<Void> tooManyRequests(ServerWebExchange exchange, Duration window) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        response.getHeaders().set("Retry-After", String.valueOf(window.toSeconds()));
        String correlationId = correlation(exchange);
        if (correlationId == null || correlationId.isBlank()) correlationId = UUID.randomUUID().toString();
        String body = "{\"error\":\"TOO_MANY_REQUESTS\",\"message\":\"Muitas requisições. Tente novamente em instantes.\",\"correlationId\":\""
                + correlationId + "\",\"timestamp\":\"" + java.time.Instant.now() + "\"}";
        DataBuffer buffer = response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }

    private String correlation(ServerWebExchange exchange) {
        return exchange.getRequest().getHeaders().getFirst(CorrelationIdGlobalFilter.HEADER);
    }

    @Override
    public int getOrder() {
        // After CorrelationId (-200) so the 429 carries a correlation id, but before auth/entitlement.
        return -150;
    }
}
