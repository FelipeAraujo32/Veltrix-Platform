package br.com.veltrix.auth.infrastructure;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

/** Prova o invariante fail-closed do perfil prod: segredo ausente/em branco derruba o startup. */
class ProdSecretsGuardTest {

    private MockEnvironment complete() {
        return new MockEnvironment()
                .withProperty("spring.datasource.url", "jdbc:sqlserver://db:1433;databaseName=veltrix_auth")
                .withProperty("spring.datasource.username", "sa")
                .withProperty("spring.datasource.password", "s3cr3t")
                .withProperty("jwt.private-key-path", "/run/secrets/veltrix-jwt-private.pem")
                .withProperty("jwt.key-id", "veltrix-2026-01")
                .withProperty("security.allowed-origins", "https://app.veltrix.com.br");
    }

    @Test
    void refusesStartupWhenSecretsAreMissing() {
        assertThatThrownBy(() -> new ProdSecretsGuard(new MockEnvironment()).postProcessBeanFactory(null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("spring.datasource.password")
                .hasMessageContaining("jwt.private-key-path")
                .hasMessageContaining("Refusing to start");
    }

    @Test
    void refusesStartupWhenSecretIsBlank() {
        MockEnvironment environment = complete().withProperty("spring.datasource.password", "   ");
        assertThatThrownBy(() -> new ProdSecretsGuard(environment).postProcessBeanFactory(null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("spring.datasource.password");
    }

    @Test
    void refusesStartupWhenPlaceholderIsUnresolvable() {
        MockEnvironment environment = complete().withProperty("spring.datasource.password", "${DB_PASSWORD}");
        assertThatThrownBy(() -> new ProdSecretsGuard(environment).postProcessBeanFactory(null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("spring.datasource.password");
    }

    @Test
    void startsWhenEverythingIsConfigured() {
        assertThatCode(() -> new ProdSecretsGuard(complete()).postProcessBeanFactory(null))
                .doesNotThrowAnyException();
    }
}
