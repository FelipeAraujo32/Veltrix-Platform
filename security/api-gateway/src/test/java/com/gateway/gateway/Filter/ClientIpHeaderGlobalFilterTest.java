package com.gateway.gateway.Filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

import java.net.InetSocketAddress;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

class ClientIpHeaderGlobalFilterTest {

    private ServerWebExchange filteredExchange(ClientIpHeaderGlobalFilter filter, MockServerWebExchange exchange) {
        GatewayFilterChain chain = mock(GatewayFilterChain.class);
        var captor = ArgumentCaptor.forClass(ServerWebExchange.class);
        when(chain.filter(any())).thenReturn(Mono.empty());
        filter.filter(exchange, chain).block();
        verify(chain).filter(captor.capture());
        return captor.getValue();
    }

    @Test
    void spoofedIncomingHeaderIsAlwaysOverwrittenWithResolvedPeerIp() {
        var filter = new ClientIpHeaderGlobalFilter(new ClientIpResolver(List.of()));
        var exchange = MockServerWebExchange.from(MockServerHttpRequest
                .post("/api/v1/auth/login")
                .header(ClientIpHeaderGlobalFilter.HEADER, "1.2.3.4") // attacker-supplied
                .remoteAddress(new InetSocketAddress("203.0.113.9", 55000)));

        var downstream = filteredExchange(filter, exchange);

        assertThat(downstream.getRequest().getHeaders().get(ClientIpHeaderGlobalFilter.HEADER))
                .containsExactly("203.0.113.9");
    }

    @Test
    void publishesRealClientIpFromTrustedLbForwardedFor() {
        var filter = new ClientIpHeaderGlobalFilter(new ClientIpResolver(List.of("10.0.0.0/8")));
        var exchange = MockServerWebExchange.from(MockServerHttpRequest
                .post("/api/v1/auth/login")
                .header("X-Forwarded-For", "198.51.100.7")
                .remoteAddress(new InetSocketAddress("10.0.0.1", 55000)));

        var downstream = filteredExchange(filter, exchange);

        assertThat(downstream.getRequest().getHeaders().getFirst(ClientIpHeaderGlobalFilter.HEADER))
                .isEqualTo("198.51.100.7");
    }
}
