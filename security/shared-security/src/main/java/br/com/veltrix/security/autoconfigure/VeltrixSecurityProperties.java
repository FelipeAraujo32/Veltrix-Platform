package br.com.veltrix.security.autoconfigure;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Resource-server settings shared by every Veltrix backend module. Bound from the same
 * {@code jwt.*} keys the existing services already use, so a new module only needs to
 * declare them (no security code).
 *
 * <p>Fail-closed: as três chaves são obrigatórias e não podem ficar em branco — um módulo
 * com configuração JWT ausente/vazia não sobe, em vez de subir sem validar issuer/audience.</p>
 */
@Validated
@ConfigurationProperties(prefix = "jwt")
public record VeltrixSecurityProperties(@NotBlank String jwkSetUri, @NotBlank String issuer, @NotBlank String audience) {
}
