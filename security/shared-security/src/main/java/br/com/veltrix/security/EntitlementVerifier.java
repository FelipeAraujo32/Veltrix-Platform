package br.com.veltrix.security;

public interface EntitlementVerifier {
    EntitlementDecision verify(AccessContext context, String serviceKey);
}
