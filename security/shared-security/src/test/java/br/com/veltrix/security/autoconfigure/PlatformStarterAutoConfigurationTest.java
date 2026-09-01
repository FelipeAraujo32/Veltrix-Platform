package br.com.veltrix.security.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import br.com.veltrix.security.EntitlementAuthorizationAspect;
import br.com.veltrix.security.EntitlementDecision;
import br.com.veltrix.security.EntitlementVerifier;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;

/** Proves the Platform Starter wires enforcement automatically yet backs off whenever a module already configures its own. */
class PlatformStarterAutoConfigurationTest {

    private final ApplicationContextRunner entitlement = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    VeltrixEntitlementClientAutoConfiguration.class,
                    VeltrixEntitlementAspectAutoConfiguration.class));

    private final WebApplicationContextRunner resourceServer = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(VeltrixResourceServerAutoConfiguration.class));

    @Test
    void providesDefaultVerifierAndAspectWhenBillingUriIsConfigured() {
        entitlement.withPropertyValues("veltrix.entitlement.billing-uri=http://localhost:8084")
                .run(context -> {
                    assertThat(context).hasSingleBean(EntitlementVerifier.class);
                    assertThat(context).hasSingleBean(EntitlementAuthorizationAspect.class);
                });
    }

    @Test
    void backsOffEntirelyWhenModuleOwnsEntitlementData() {
        entitlement.run(context -> {
            assertThat(context).doesNotHaveBean(EntitlementVerifier.class);
            assertThat(context).doesNotHaveBean(EntitlementAuthorizationAspect.class);
        });
    }

    @Test
    void keepsModuleProvidedVerifierAndStillWiresAspect() {
        entitlement.withUserConfiguration(UserVerifierConfig.class).run(context -> {
            assertThat(context).hasSingleBean(EntitlementVerifier.class);
            assertThat(context.getBean(EntitlementVerifier.class)).isSameAs(context.getBean("userVerifier"));
            assertThat(context).hasSingleBean(EntitlementAuthorizationAspect.class);
        });
    }

    @Test
    void resourceServerBacksOffWhenModuleDeclaresItsOwnFilterChain() {
        resourceServer
                .withPropertyValues("jwt.jwk-set-uri=http://localhost:8082/.well-known/jwks.json",
                        "jwt.issuer=veltrix-auth", "jwt.audience=veltrix-platform")
                .withUserConfiguration(UserFilterChainConfig.class)
                .run(context -> assertThat(context).doesNotHaveBean(JwtDecoder.class));
    }

    /** Fail-closed: configuração jwt.* em branco derruba o startup do módulo (@Validated/@NotBlank). */
    @Test
    void refusesToStartWhenJwtConfigurationIsBlank() {
        resourceServer
                .withPropertyValues("jwt.jwk-set-uri=http://localhost:8082/.well-known/jwks.json",
                        "jwt.issuer=", "jwt.audience=veltrix-platform")
                .withUserConfiguration(UserFilterChainConfig.class)
                .run(context -> assertThat(context).hasFailed());
    }

    @Configuration
    static class UserVerifierConfig {
        @Bean
        EntitlementVerifier userVerifier() {
            return (context, serviceKey) -> new EntitlementDecision(true, "ACTIVE", null, Map.of(), Map.of());
        }
    }

    @Configuration
    static class UserFilterChainConfig {
        @Bean
        SecurityFilterChain userChain() {
            return new DefaultSecurityFilterChain(AnyRequestMatcher.INSTANCE);
        }
    }
}
