package com.gateway.gateway.Filter;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;

/**
 * Resolves the client IP for rate-limiting. {@code X-Forwarded-For} is only honoured when the direct
 * peer (the TCP remote address) matches a configured trusted proxy — exact IP or CIDR block (e.g.
 * {@code 10.0.0.0/8} for a Docker/LB subnet without fixed IPs). Otherwise the header is
 * attacker-controlled and would let a single caller forge unlimited distinct keys, defeating the limiter.
 * When trusted, the left-most XFF entry (the original client) is used; otherwise we fall back to the
 * socket remote address. Invalid trust entries are skipped (fail-safe: distrust).
 */
public class ClientIpResolver {
    private static final Logger LOG = LoggerFactory.getLogger(ClientIpResolver.class);
    private static final String XFF = "X-Forwarded-For";
    private final List<Network> trustedProxies;

    public ClientIpResolver(List<String> trustedProxies) {
        this.trustedProxies = parse(trustedProxies);
    }

    public String resolve(ServerHttpRequest request) {
        InetAddress peer = remoteAddress(request);
        if (peer != null && isTrusted(peer)) {
            String forwarded = request.getHeaders().getFirst(XFF);
            if (forwarded != null && !forwarded.isBlank()) {
                String first = forwarded.split(",", 2)[0].trim();
                if (!first.isEmpty()) return first;
            }
        }
        return peer == null ? "unknown" : peer.getHostAddress();
    }

    private boolean isTrusted(InetAddress peer) {
        byte[] candidate = peer.getAddress();
        for (Network network : trustedProxies) {
            if (network.contains(candidate)) return true;
        }
        return false;
    }

    private InetAddress remoteAddress(ServerHttpRequest request) {
        InetSocketAddress address = request.getRemoteAddress();
        return address == null ? null : address.getAddress();
    }

    private static List<Network> parse(List<String> entries) {
        List<Network> parsed = new ArrayList<>();
        for (String raw : entries == null ? List.<String>of() : entries) {
            String entry = raw == null ? "" : raw.trim();
            if (entry.isEmpty()) continue;
            try {
                String host = entry;
                int prefix = -1;
                int slash = entry.indexOf('/');
                if (slash >= 0) {
                    host = entry.substring(0, slash);
                    prefix = Integer.parseInt(entry.substring(slash + 1));
                }
                // IP literals only — never resolve hostnames (no DNS on config parsing).
                if (!host.matches("[0-9a-fA-F:.]+")) throw new IllegalArgumentException("not an IP literal");
                byte[] address = InetAddress.getByName(host).getAddress();
                int maxPrefix = address.length * 8;
                if (prefix < 0) prefix = maxPrefix;
                if (prefix > maxPrefix) throw new IllegalArgumentException("prefix out of range");
                parsed.add(new Network(address, prefix));
            } catch (Exception e) {
                LOG.warn("Ignoring invalid trusted-proxy entry '{}' ({})", entry, e.getMessage());
            }
        }
        return List.copyOf(parsed);
    }

    record Network(byte[] address, int prefix) {
        boolean contains(byte[] candidate) {
            if (candidate.length != address.length) return false;
            int fullBytes = prefix / 8, remainder = prefix % 8;
            for (int i = 0; i < fullBytes; i++) {
                if (address[i] != candidate[i]) return false;
            }
            if (remainder == 0) return true;
            int mask = (0xFF << (8 - remainder)) & 0xFF;
            return (address[fullBytes] & mask) == (candidate[fullBytes] & mask);
        }
    }
}
