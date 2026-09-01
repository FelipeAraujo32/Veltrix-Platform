package br.com.veltrix.auth.infrastructure;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

class ClientIpResolverTest {

    private MockHttpServletRequest request(String remoteAddr, String forwardedFor) {
        var request = new MockHttpServletRequest("POST", "/api/v1/auth/login");
        request.setRemoteAddr(remoteAddr);
        if (forwardedFor != null) request.addHeader("X-Forwarded-For", forwardedFor);
        return request;
    }

    @Test
    void withoutTrustedProxiesXffIsIgnoredEvenFromGateway() {
        // Misconfiguration guard: empty trust list means the socket peer wins (fail-safe vs spoofing),
        // which is why AUTH_TRUSTED_PROXIES is mandatory behind a gateway/LB.
        var resolver = new ClientIpResolver(List.of());
        assertThat(resolver.resolve(request("172.18.0.5", "198.51.100.7"))).isEqualTo("172.18.0.5");
    }

    @Test
    void honoursXffFromExactTrustedProxyIp() {
        var resolver = new ClientIpResolver(List.of("172.18.0.5"));
        assertThat(resolver.resolve(request("172.18.0.5", "198.51.100.7, 172.18.0.5"))).isEqualTo("198.51.100.7");
    }

    @Test
    void honoursXffFromTrustedCidrSubnet() {
        // Docker/LB subnets rarely have fixed IPs — CIDR trust makes the config feasible.
        var resolver = new ClientIpResolver(List.of("172.18.0.0/16"));
        assertThat(resolver.resolve(request("172.18.42.9", "198.51.100.7"))).isEqualTo("198.51.100.7");
    }

    @Test
    void rejectsXffFromPeerOutsideCidr() {
        var resolver = new ClientIpResolver(List.of("172.18.0.0/16"));
        assertThat(resolver.resolve(request("172.19.0.1", "198.51.100.7"))).isEqualTo("172.19.0.1");
    }

    @Test
    void invalidTrustEntriesAreSkippedFailSafe() {
        var resolver = new ClientIpResolver(List.of("gateway-hostname", "10.0.0.0/99", ""));
        assertThat(resolver.resolve(request("172.18.0.5", "198.51.100.7"))).isEqualTo("172.18.0.5");
    }

    @Test
    void fallsBackToPeerWhenXffMissing() {
        var resolver = new ClientIpResolver(List.of("172.18.0.0/16"));
        assertThat(resolver.resolve(request("172.18.0.5", null))).isEqualTo("172.18.0.5");
    }

    @Test
    void prefersGatewayInjectedHeaderOverXffFromTrustedPeer() {
        // SCG 5 trusted-proxies filters public IPs out of the forwarded XFF chain, so the gateway
        // publishes the IP it resolved in X-Veltrix-Client-Ip — that is the authoritative source.
        var resolver = new ClientIpResolver(List.of("172.18.0.0/16"));
        var req = request("172.18.0.5", "10.9.9.9"); // XFF only carries filtered/internal hops
        req.addHeader("X-Veltrix-Client-Ip", "198.51.100.7");
        assertThat(resolver.resolve(req)).isEqualTo("198.51.100.7");
    }

    @Test
    void ignoresGatewayHeaderFromUntrustedPeer() {
        // Direct hit bypassing the gateway: the dedicated header is attacker-controlled and must be ignored.
        var resolver = new ClientIpResolver(List.of("172.18.0.0/16"));
        var req = request("203.0.113.66", null);
        req.addHeader("X-Veltrix-Client-Ip", "198.51.100.7");
        assertThat(resolver.resolve(req)).isEqualTo("203.0.113.66");
    }
}
