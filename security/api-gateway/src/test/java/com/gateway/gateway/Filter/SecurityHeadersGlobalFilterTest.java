package com.gateway.gateway.Filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;

class SecurityHeadersGlobalFilterTest {

    private static SecurityHeadersGlobalFilter defaultFilter() {
        return new SecurityHeadersGlobalFilter(true, SecurityHeadersGlobalFilter.DEFAULT_HSTS_VALUE);
    }

    private static HttpHeaders run(SecurityHeadersGlobalFilter filter) {
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/v1/me").build());
        GatewayFilterChain chain = mock(GatewayFilterChain.class);
        when(chain.filter(exchange)).thenReturn(Mono.empty());
        filter.filter(exchange, chain).block();
        return exchange.getResponse().getHeaders();
    }

    @Test
    void emitsHstsWithOneYearMaxAgeAndIncludeSubDomains() {
        assertThat(run(defaultFilter()).getFirst("Strict-Transport-Security"))
                .isEqualTo("max-age=31536000; includeSubDomains");
    }

    @Test
    void keepsExistingSecurityHeadersAlongsideHsts() {
        HttpHeaders headers = run(defaultFilter());
        assertThat(headers.getFirst("Strict-Transport-Security")).isNotBlank();
        assertThat(headers.getFirst("Content-Security-Policy")).contains("default-src 'self'").contains("frame-ancestors 'none'");
        assertThat(headers.getFirst("Permissions-Policy")).contains("camera=()");
        assertThat(headers.getFirst("X-Frame-Options")).isEqualTo("DENY");
        assertThat(headers.getFirst("Cross-Origin-Opener-Policy")).isEqualTo("same-origin");
    }

    @Test
    void hstsValueIsConfigurable() {
        var filter = new SecurityHeadersGlobalFilter(true, "max-age=63072000; includeSubDomains; preload");
        assertThat(run(filter).getFirst("Strict-Transport-Security"))
                .isEqualTo("max-age=63072000; includeSubDomains; preload");
    }

    @Test
    void disablingHstsForLocalDevNeverDropsTheOtherHeaders() {
        HttpHeaders headers = run(new SecurityHeadersGlobalFilter(false, SecurityHeadersGlobalFilter.DEFAULT_HSTS_VALUE));
        assertThat(headers.getFirst("Strict-Transport-Security")).isNull();
        assertThat(headers.getFirst("Content-Security-Policy")).isNotBlank();
        assertThat(headers.getFirst("X-Frame-Options")).isEqualTo("DENY");
    }
}
