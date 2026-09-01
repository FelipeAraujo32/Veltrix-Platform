package com.gateway.gateway.Filter;

import static org.assertj.core.api.Assertions.assertThat;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * End-to-end regression guard for W1.4 (F2): proves the gateway STRIPS X-Forwarded-* / Forwarded
 * arriving from an UNTRUSTED remote address before proxying downstream — the fail-closed behavior
 * that defends against XFF and host-header spoofing.
 *
 * A plain JDK HttpServer stands in for the downstream service and records the headers it receives.
 * Its (ephemeral) port is wired into the gateway route via @DynamicPropertySource, which resolves
 * before context refresh, so the route URI is concrete (unlike ${local.server.port}, unknown at
 * route-build time). The WebTestClient connects from 127.0.0.1; trusted-proxies is set to a bogus
 * address excluding loopback, so the gateway treats the caller as untrusted and must drop the forged
 * headers. (The trusted-relay direction cannot be reproduced locally because the test client's
 * source IP is always loopback; it is asserted structurally in GatewayApplicationTests.)
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles({"test", "fwdtest"})
class ForwardedHeadersRelayTest {

    private static HttpServer stub;
    private static final Map<String, List<String>> received = new ConcurrentHashMap<>();

    @Value("${local.server.port}")
    int port;

    @BeforeAll
    static void startStub() throws IOException {
        stub = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        stub.createContext("/api/v1/auth/probe", exchange -> {
            received.clear();
            received.putAll(exchange.getRequestHeaders());
            byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        stub.start();
    }

    @AfterAll
    static void stopStub() {
        if (stub != null) stub.stop(0);
    }

    @DynamicPropertySource
    static void routeUri(DynamicPropertyRegistry registry) {
        registry.add("PROBE_STUB_URI", () -> "http://127.0.0.1:" + stub.getAddress().getPort());
    }

    @Test
    void forgedForwardedHeadersFromUntrustedClientAreStripped() {
        WebTestClient.bindToServer().baseUrl("http://localhost:" + port).build()
                .get().uri("/api/v1/auth/probe")
                .header("X-Forwarded-Proto", "https")
                .header("X-Forwarded-Host", "evil.example.com")
                .header("X-Forwarded-For", "1.2.3.4")
                .header("Forwarded", "host=evil.example.com;proto=https")
                .exchange()
                .expectStatus().isOk();

        // Untrusted caller (loopback not in trusted-proxies) => gateway must strip all forwarded headers.
        assertThat(received.keySet().stream().map(String::toLowerCase))
                .doesNotContain("x-forwarded-host", "x-forwarded-for", "forwarded");
    }
}
