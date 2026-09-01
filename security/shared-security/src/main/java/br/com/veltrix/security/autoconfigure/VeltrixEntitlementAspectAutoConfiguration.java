package br.com.veltrix.security.autoconfigure;

import br.com.veltrix.security.EntitlementAuthorizationAspect;
import br.com.veltrix.security.EntitlementVerifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

/**
 * Enables {@code @RequiresEntitlement} enforcement whenever an {@link EntitlementVerifier}
 * is present (either the starter's default HTTP one or a module-provided bean). Runs after
 * {@link VeltrixEntitlementClientAutoConfiguration} so the conditional reliably sees the
 * default verifier. Spring Boot's AOP auto-configuration provides the proxying.
 */
@AutoConfiguration(after = VeltrixEntitlementClientAutoConfiguration.class)
@ConditionalOnClass(EntitlementAuthorizationAspect.class)
@ConditionalOnBean(EntitlementVerifier.class)
public class VeltrixEntitlementAspectAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    EntitlementAuthorizationAspect entitlementAuthorizationAspect(EntitlementVerifier verifier) {
        return new EntitlementAuthorizationAspect(verifier);
    }
}
