package br.com.veltrix.security.autoconfigure;

import br.com.veltrix.security.EntitlementDecision;
import br.com.veltrix.security.EntitlementVerifier;
import java.time.Instant;
import java.util.Map;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.client.RestClient;

/**
 * Default {@link EntitlementVerifier} that forwards the caller's JWT to billing-service and
 * asks whether the current tenant/base may use a given {@code serviceKey}. This is the
 * boilerplate every business module used to copy (see the old ouvidoria CommercialEntitlementConfig);
 * now a module gets it for free by setting {@code veltrix.entitlement.billing-uri}. A module that
 * needs custom logic can still declare its own {@code EntitlementVerifier} and this backs off.
 */
@AutoConfiguration
@ConditionalOnClass({EntitlementVerifier.class, RestClient.class})
@EnableConfigurationProperties(VeltrixEntitlementProperties.class)
public class VeltrixEntitlementClientAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(EntitlementVerifier.class)
    @ConditionalOnProperty(prefix = "veltrix.entitlement", name = "billing-uri")
    EntitlementVerifier billingEntitlementVerifier(VeltrixEntitlementProperties props) {
        RestClient client = RestClient.create(props.billingUri());
        String path = props.checkPath();
        return (context, serviceKey) -> {
            Object principal = SecurityContextHolder.getContext().getAuthentication() == null
                    ? null : SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            if (!(principal instanceof Jwt jwt)) return denied("UNAUTHENTICATED");
            try {
                Response response = client.post().uri(path)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt.getTokenValue())
                        .body(new Request(context.tenantId(), context.baseId(), serviceKey))
                        .retrieve().body(Response.class);
                return response == null ? denied("UNAVAILABLE")
                        : new EntitlementDecision(response.allowed(), response.status(), response.validUntil(), Map.of(), Map.of());
            } catch (RuntimeException unavailable) {
                return denied("TEMPORARILY_UNAVAILABLE");
            }
        };
    }

    private static EntitlementDecision denied(String status) {
        return new EntitlementDecision(false, status, null, Map.of(), Map.of());
    }

    record Request(String tenantId, String baseId, String serviceKey) {}
    record Response(boolean allowed, String status, Instant validUntil) {}
}
