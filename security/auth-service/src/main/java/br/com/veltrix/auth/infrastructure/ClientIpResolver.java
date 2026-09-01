package br.com.veltrix.auth.infrastructure;

import jakarta.servlet.http.HttpServletRequest;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Resolves the real client IP for login lockout. auth-service normally sits behind the gateway, whose
 * SCG 5 {@code trusted-proxies} mode FILTERS the forwarded {@code X-Forwarded-For} chain (post
 * CVE-2025-41235) — public client IPs never arrive here via XFF. The gateway therefore publishes the IP
 * it resolved itself in the dedicated internal header {@code X-Veltrix-Client-Ip} (always overwritten at
 * the edge, so it cannot be spoofed through the gateway). This resolver prefers that header, falls back
 * to the first XFF entry (for topologies without the Veltrix gateway, e.g. behind a plain LB), then the
 * socket peer. Both headers are honoured ONLY when the direct peer ({@code getRemoteAddr()}) matches a
 * configured trusted proxy — exact IP or CIDR block (e.g. {@code 172.18.0.0/16} for a Docker subnet
 * without fixed IPs); otherwise they are attacker-controlled and would let one caller forge unlimited
 * lockout keys.
 *
 * <p><b>MANDATORY behind a gateway/LB</b>: configure {@code security.trusted-proxies}
 * ({@code AUTH_TRUSTED_PROXIES}). Without it, every client resolves to the gateway's IP, the per
 * account+IP lockout key degenerates to account+constant and a cheap attacker can lock a victim's
 * account (see the account-level threshold in {@link LoginAttemptService} for the bounded fallback).
 * Invalid entries are skipped (fail-safe: distrust).
 */
@Component
public class ClientIpResolver {
    private static final Logger LOG = LoggerFactory.getLogger(ClientIpResolver.class);
    /** Set by the gateway with the client IP it resolved at the edge; generic platform infra. */
    static final String CLIENT_IP_HEADER = "X-Veltrix-Client-Ip";
    private static final String XFF = "X-Forwarded-For";
    private final List<Network> trustedProxies;

    public ClientIpResolver(@Value("${security.trusted-proxies:}") List<String> trustedProxies) {
        this.trustedProxies = parse(trustedProxies);
    }

    public String resolve(HttpServletRequest request) {
        String remote = request.getRemoteAddr();
        if (remote != null && isTrusted(remote)) {
            String dedicated = request.getHeader(CLIENT_IP_HEADER);
            if (StringUtils.hasText(dedicated)) return dedicated.trim();
            String forwarded = request.getHeader(XFF);
            if (StringUtils.hasText(forwarded)) {
                String first = forwarded.split(",", 2)[0].trim();
                if (!first.isEmpty()) return first;
            }
        }
        return remote == null ? "unknown" : remote;
    }

    private boolean isTrusted(String remote) {
        if (trustedProxies.isEmpty()) return false;
        try {
            byte[] candidate = InetAddress.getByName(remote).getAddress(); // remote is an IP literal, no DNS
            for (Network network : trustedProxies) {
                if (network.contains(candidate)) return true;
            }
        } catch (Exception e) {
            LOG.warn("Could not parse remote address '{}' for proxy trust check", remote);
        }
        return false;
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
