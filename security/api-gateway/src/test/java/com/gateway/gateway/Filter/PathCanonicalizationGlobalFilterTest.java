package com.gateway.gateway.Filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

import java.net.URI;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Edge canonicalization guard. Any non-canonical RAW path must be rejected with 400 BEFORE it can reach
 * the Jwt public-path matcher, the RateLimit exempt-path matcher, the Entitlement service-key resolver or
 * the router. Legitimate public/exempt paths must flow through untouched.
 */
class PathCanonicalizationGlobalFilterTest {

    private final PathCanonicalizationGlobalFilter filter = new PathCanonicalizationGlobalFilter();

    /** Build an exchange whose RAW path is exactly {@code rawPath} (bypasses MockServerHttpRequest normalization). */
    private MockServerWebExchange exchangeWithRawPath(String rawPath) {
        return MockServerWebExchange.from(
                MockServerHttpRequest.method(HttpMethod.GET, URI.create("http://gw" + rawPath)));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/api/v1/billing/webhooks/../secret",   // dot-segment escaping exempt-path (W1.5)
            "/api/v1/auth/../billing/internal",       // dot-segment escaping public-path
            "/api/v1/ouvidoria/q/../../me",           // traversal out of public prefix
            "/api/v1/%2e%2e/billing",                  // encoded dot-segment
            "/api/v1/auth/%2E%2E/x",                   // encoded dot-segment (upper case)
            "/api/v1/billing%2fwebhooks",             // encoded forward slash
            "/api/v1/billing%2Fwebhooks",             // encoded forward slash (upper case)
            "/api/v1//billing/webhooks",              // empty segment (double slash)
            "/api/v1/billing/webhooks//x",            // trailing double slash
            "/api/v1/billing%5cwebhooks",             // encoded backslash
            "/api/v1/billing%5Cwebhooks",             // encoded backslash (upper case)
    })
    void rejectsNonCanonicalPathsWith400(String rawPath) {
        var exchange = exchangeWithRawPath(rawPath);
        GatewayFilterChain chain = mock(GatewayFilterChain.class);

        filter.filter(exchange, chain).block();

        verify(chain, never()).filter(any());
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        String body = exchange.getResponse().getBodyAsString().block();
        assertThat(body).contains("\"error\":\"INVALID_REQUEST\"").contains("\"message\"");
        // Never reflect the offending path back to the caller.
        assertThat(body).doesNotContain("billing").doesNotContain("secret").doesNotContain("..");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/api/v1/ouvidoria/q/abc",                                 // real public-path (ouvidoria/q/**)
            "/api/v1/billing/webhooks/asaas",                          // real exempt-path + public-path
            "/api/v1/auth/login",                                       // real public-path (auth/**)
            "/api/v1/ouvidoria/manifestacoes",                         // real public-path
            "/api/v1/ouvidoria/manifestacoes/OUV-1/anexos/9",         // real public-path (nested)
            "/.well-known/jwks.json",                                   // real public-path
            "/actuator/health",                                         // real public-path
            "/api/v1/me",                                               // protected but canonical
            "/api/v1/finance/summary",                                  // protected module, canonical
    })
    void allowsLegitimateCanonicalPaths(String rawPath) {
        var exchange = exchangeWithRawPath(rawPath);
        GatewayFilterChain chain = mock(GatewayFilterChain.class);
        when(chain.filter(exchange)).thenReturn(Mono.empty());

        filter.filter(exchange, chain).block();

        verify(chain).filter(exchange);
        assertThat(exchange.getResponse().getStatusCode()).isNull();
    }

    @Test
    void detectsRawCharsUnrepresentableInAConstructedUri() {
        // These bytes can arrive on the wire (Netty exposes them via getRawPath) but java.net.URI
        // rejects them, so the end-to-end exchange test cannot build them. Exercise the guard directly.
        assertThat(filter.isNonCanonical("/api/v1/billing\\webhooks")).as("literal backslash").isTrue();
        assertThat(filter.isNonCanonical("/api/v1/auth/login" + (char) 0x00)).as("NUL").isTrue();
        assertThat(filter.isNonCanonical("/api/v1/auth/login" + (char) 0x0d + (char) 0x0a)).as("CRLF").isTrue();
        assertThat(filter.isNonCanonical("/api/v1/auth/login" + (char) 0x7f)).as("DEL").isTrue();
        assertThat(filter.isNonCanonical("/api/v1/auth/login" + (char) 0x09)).as("TAB").isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/api/v1/ouvidoria/q/abc",
            "/api/v1/billing/webhooks/asaas",
            "/api/v1/auth/login",
            "/.well-known/jwks.json",
    })
    void treatsLegitimateRawPathsAsCanonical(String rawPath) {
        assertThat(filter.isNonCanonical(rawPath)).isFalse();
    }

    @Test
    void propagatesCorrelationIdOnRejectionWhenPresent() {
        var exchange = MockServerWebExchange.from(MockServerHttpRequest
                .method(HttpMethod.GET, URI.create("http://gw/api/v1/billing/webhooks/../x"))
                .header(CorrelationIdGlobalFilter.HEADER, "corr-123"));
        GatewayFilterChain chain = mock(GatewayFilterChain.class);

        filter.filter(exchange, chain).block();

        assertThat(exchange.getResponse().getHeaders().getFirst(CorrelationIdGlobalFilter.HEADER)).isEqualTo("corr-123");
        assertThat(exchange.getResponse().getBodyAsString().block()).contains("corr-123");
    }

    @Test
    void generatesCorrelationIdOnRejectionWhenAbsent() {
        var exchange = exchangeWithRawPath("/api/v1/auth/../x");
        GatewayFilterChain chain = mock(GatewayFilterChain.class);

        filter.filter(exchange, chain).block();

        String header = exchange.getResponse().getHeaders().getFirst(CorrelationIdGlobalFilter.HEADER);
        assertThat(header).isNotBlank();
    }

    @Test
    void runsBeforeCorrelationAndSecurityHeaderFilters() {
        // Must sit at the absolute edge: strictly before -200 (Correlation/SecurityHeaders).
        assertThat(filter.getOrder()).isLessThan(-200);
    }

    @Test
    void publicPathMatcherReceivesOnlyCanonicalPathAfterGuard() {
        // Proof: a traversal aimed at an exempt/public prefix is rejected here, so the downstream
        // PublicPathMatcher / RateLimit exempt matcher only ever see canonical input.
        PublicPathMatcher publicPaths = new PublicPathMatcher(java.util.List.of("/api/v1/billing/webhooks/**"));
        // The raw attack string would ant-match the exempt prefix if it ever reached the matcher...
        assertThat(publicPaths.isPublic("/api/v1/billing/webhooks/anything")).isTrue();
        // ...but the guard rejects it before the chain, so the matcher is never consulted with it.
        var exchange = exchangeWithRawPath("/api/v1/billing/webhooks/../../me");
        GatewayFilterChain chain = mock(GatewayFilterChain.class);

        filter.filter(exchange, chain).block();

        verify(chain, never()).filter(any());
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }
}
