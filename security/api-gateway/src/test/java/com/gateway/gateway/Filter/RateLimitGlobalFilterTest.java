package com.gateway.gateway.Filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import com.gateway.gateway.Config.RateLimitProperties;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

class RateLimitGlobalFilterTest {

    private final ReactiveStringRedisTemplate redis = mock(ReactiveStringRedisTemplate.class);
    private final RateLimitProperties props = new RateLimitProperties(
            true, 3, Duration.ofMinutes(1), 100, Duration.ofMinutes(1), List.of(),
            List.of("/api/v1/billing/webhooks/**"));
    private final ClientIpResolver clientIp = new ClientIpResolver(List.of());
    private final RateLimitGlobalFilter filter =
            new RateLimitGlobalFilter(redis, clientIp, props);

    private MockServerWebExchange loginExchange() {
        return MockServerWebExchange.from(MockServerHttpRequest
                .post("/api/v1/auth/login")
                .remoteAddress(new InetSocketAddress("203.0.113.9", 55000)));
    }

    private void stubCount(long count) {
        when(redis.execute(ArgumentMatchers.<RedisScript<Long>>any(), anyList(), anyList()))
                .thenReturn(Flux.just(count));
    }

    @Test
    void allowsLoginUnderLimit() {
        stubCount(1L);
        var exchange = loginExchange();
        GatewayFilterChain chain = mock(GatewayFilterChain.class);
        when(chain.filter(exchange)).thenReturn(Mono.empty());

        filter.filter(exchange, chain).block();

        verify(chain).filter(exchange);
        assertThat(exchange.getResponse().getStatusCode()).isNull();
    }

    @Test
    void rejectsLoginOverLimitWith429AndStandardBody() {
        // count 4 > limit 3
        stubCount(4L);
        var exchange = loginExchange();
        GatewayFilterChain chain = mock(GatewayFilterChain.class);

        filter.filter(exchange, chain).block();

        verify(chain, never()).filter(any());
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(exchange.getResponse().getHeaders().getFirst("Retry-After")).isEqualTo("60");
        String body = exchange.getResponse().getBodyAsString().block();
        assertThat(body).contains("\"error\":\"TOO_MANY_REQUESTS\"").contains("\"message\"");
    }

    @Test
    void failsOpenWhenRedisUnavailable() {
        when(redis.execute(ArgumentMatchers.<RedisScript<Long>>any(), anyList(), anyList()))
                .thenReturn(Flux.error(new RuntimeException("redis down")));
        var exchange = loginExchange();
        GatewayFilterChain chain = mock(GatewayFilterChain.class);
        when(chain.filter(exchange)).thenReturn(Mono.empty());

        filter.filter(exchange, chain).block();

        verify(chain).filter(exchange);
    }

    @Test
    void usesLooserGlobalBucketForNonLoginRequests() {
        // global limit is 100; a count of 50 must pass
        stubCount(50L);
        var exchange = MockServerWebExchange.from(MockServerHttpRequest
                .get("/api/v1/me")
                .remoteAddress(new InetSocketAddress("203.0.113.9", 55000)));
        GatewayFilterChain chain = mock(GatewayFilterChain.class);
        when(chain.filter(exchange)).thenReturn(Mono.empty());

        filter.filter(exchange, chain).block();

        verify(chain).filter(exchange);
        // key must be the global bucket, not login
        verify(redis).execute(ArgumentMatchers.<RedisScript<Long>>any(),
                eq(List.of("ratelimit:global:203.0.113.9")), anyList());
    }

    @Test
    void exemptPathBypassesLimiterEntirely() {
        // Payment webhook path is exempt via configuration: no Redis interaction, request flows through.
        var exchange = MockServerWebExchange.from(MockServerHttpRequest
                .post("/api/v1/billing/webhooks/asaas")
                .remoteAddress(new InetSocketAddress("203.0.113.9", 55000)));
        GatewayFilterChain chain = mock(GatewayFilterChain.class);
        when(chain.filter(exchange)).thenReturn(Mono.empty());

        filter.filter(exchange, chain).block();

        verify(chain).filter(exchange);
        verifyNoInteractions(redis);
        assertThat(exchange.getResponse().getStatusCode()).isNull();
    }

    @Test
    void bypassesWhenDisabled() {
        var disabled = new RateLimitProperties(false, 3, Duration.ofMinutes(1), 100, Duration.ofMinutes(1),
                List.of(), List.of());
        var f = new RateLimitGlobalFilter(redis, clientIp, disabled);
        var exchange = loginExchange();
        GatewayFilterChain chain = mock(GatewayFilterChain.class);
        when(chain.filter(exchange)).thenReturn(Mono.empty());

        f.filter(exchange, chain).block();

        verify(chain).filter(exchange);
        verifyNoInteractions(redis);
    }

    @Test
    void honoursForwardedForOnlyFromTrustedProxy() {
        var trusting = new ClientIpResolver(List.of("10.0.0.1"));
        var req = MockServerHttpRequest.post("/api/v1/auth/login")
                .header("X-Forwarded-For", "198.51.100.7, 10.0.0.1")
                .remoteAddress(new InetSocketAddress("10.0.0.1", 40000))
                .build();
        assertThat(trusting.resolve(req)).isEqualTo("198.51.100.7");
    }

    @Test
    void honoursForwardedForFromTrustedCidrRange() {
        // LB/Docker subnets rarely have fixed IPs — trust must accept CIDR blocks.
        var trusting = new ClientIpResolver(List.of("10.0.0.0/8"));
        var req = MockServerHttpRequest.post("/api/v1/auth/login")
                .header("X-Forwarded-For", "198.51.100.7")
                .remoteAddress(new InetSocketAddress("10.42.7.13", 40000))
                .build();
        assertThat(trusting.resolve(req)).isEqualTo("198.51.100.7");
    }

    @Test
    void cidrTrustDoesNotLeakOutsideTheRange() {
        var trusting = new ClientIpResolver(List.of("10.0.0.0/8"));
        var req = MockServerHttpRequest.post("/api/v1/auth/login")
                .header("X-Forwarded-For", "198.51.100.7")
                .remoteAddress(new InetSocketAddress("11.0.0.1", 40000))
                .build();
        assertThat(trusting.resolve(req)).isEqualTo("11.0.0.1");
    }

    @Test
    void invalidTrustedProxyEntriesAreIgnoredFailSafe() {
        var trusting = new ClientIpResolver(List.of("not-a-cidr/99", ""));
        var req = MockServerHttpRequest.post("/api/v1/auth/login")
                .header("X-Forwarded-For", "198.51.100.7")
                .remoteAddress(new InetSocketAddress("203.0.113.50", 40000))
                .build();
        assertThat(trusting.resolve(req)).isEqualTo("203.0.113.50");
    }

    @Test
    void ignoresForwardedForFromUntrustedPeer() {
        var untrusting = new ClientIpResolver(List.of("10.0.0.1"));
        var req = MockServerHttpRequest.post("/api/v1/auth/login")
                .header("X-Forwarded-For", "198.51.100.7")
                .remoteAddress(new InetSocketAddress("203.0.113.50", 40000))
                .build();
        assertThat(untrusting.resolve(req)).isEqualTo("203.0.113.50");
    }
}
