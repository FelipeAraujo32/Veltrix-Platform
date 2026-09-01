package br.com.veltrix.security;

import java.time.Instant;
import java.util.Map;

public record EntitlementDecision(boolean allowed, String status, Instant validUntil,
                                  Map<String, Object> limits, Map<String, Object> features) {
    public EntitlementDecision {
        limits = limits == null ? Map.of() : Map.copyOf(limits);
        features = features == null ? Map.of() : Map.copyOf(features);
    }
}
