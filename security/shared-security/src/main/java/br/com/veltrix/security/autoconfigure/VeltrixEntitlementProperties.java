package br.com.veltrix.security.autoconfigure;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration for the default entitlement verifier that calls billing-service.
 * When {@code veltrix.entitlement.billing-uri} is absent the starter provides no
 * verifier, so services that own the entitlement data (e.g. billing itself) are untouched.
 */
@ConfigurationProperties(prefix = "veltrix.entitlement")
public record VeltrixEntitlementProperties(String billingUri, String checkPath) {
    public VeltrixEntitlementProperties {
        if (checkPath == null || checkPath.isBlank()) checkPath = "/internal/v1/entitlements/check";
    }
}
