package br.com.veltrix.security.autoconfigure;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;

/**
 * Default JWT resource-server for a Veltrix module. The whole block is gated on
 * {@link ConditionalOnMissingBean}({@link SecurityFilterChain}): any service that already
 * declares its own filter chain (billing, ouvidoria) keeps its exact configuration and the
 * starter contributes nothing. A brand-new module gets stateless JWT validation, permission
 * mapping and JSON 401/403 responses just by adding the dependency and the {@code jwt.*} keys.
 */
@AutoConfiguration
@ConditionalOnClass({SecurityFilterChain.class, JwtDecoder.class})
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableConfigurationProperties(VeltrixSecurityProperties.class)
public class VeltrixResourceServerAutoConfiguration {

    @Configuration(proxyBeanMethods = false)
    @EnableMethodSecurity
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    @ConditionalOnProperty(prefix = "jwt", name = "jwk-set-uri")
    static class DefaultResourceServer {

        @Bean
        @ConditionalOnMissingBean
        JwtDecoder jwtDecoder(VeltrixSecurityProperties props) {
            NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(props.jwkSetUri()).build();
            OAuth2TokenValidator<Jwt> issuer = JwtValidators.createDefaultWithIssuer(props.issuer());
            OAuth2TokenValidator<Jwt> audience = new JwtClaimValidator<Collection<String>>(
                    "aud", values -> values != null && values.contains(props.audience()));
            decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(issuer, audience));
            return decoder;
        }

        @Bean
        @ConditionalOnMissingBean
        Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter() {
            JwtGrantedAuthoritiesConverter authorities = new JwtGrantedAuthoritiesConverter();
            authorities.setAuthoritiesClaimName("permissions");
            authorities.setAuthorityPrefix("");
            JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
            converter.setJwtGrantedAuthoritiesConverter(authorities);
            return converter;
        }

        @Bean
        SecurityFilterChain veltrixResourceServerFilterChain(HttpSecurity http,
                Converter<Jwt, ? extends AbstractAuthenticationToken> converter,
                AuthenticationEntryPoint authenticationEntryPoint,
                AccessDeniedHandler accessDeniedHandler) throws Exception {
            return http
                    .csrf(csrf -> csrf.disable())
                    .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                    .httpBasic(basic -> basic.disable())
                    .formLogin(form -> form.disable())
                    .exceptionHandling(ex -> ex
                            .authenticationEntryPoint(authenticationEntryPoint)
                            .accessDeniedHandler(accessDeniedHandler))
                    .authorizeHttpRequests(auth -> auth
                            .requestMatchers("/actuator/health", "/actuator/health/**", "/actuator/info").permitAll()
                            .anyRequest().authenticated())
                    .oauth2ResourceServer(resource -> resource.jwt(jwt -> jwt.jwtAuthenticationConverter(converter)))
                    .build();
        }

        @Bean
        @ConditionalOnMissingBean
        AuthenticationEntryPoint veltrixAuthenticationEntryPoint() {
            return (request, response, ex) -> writeError(request, response, 401, "UNAUTHORIZED", "Autenticação obrigatória");
        }

        @Bean
        @ConditionalOnMissingBean
        AccessDeniedHandler veltrixAccessDeniedHandler() {
            return (request, response, ex) -> writeError(request, response, 403, "FORBIDDEN", "Acesso não permitido");
        }

        private static void writeError(HttpServletRequest request, HttpServletResponse response,
                int status, String error, String message) throws IOException {
            response.setStatus(status);
            String correlationId = request.getHeader("X-Correlation-Id");
            if (correlationId != null) response.setHeader("X-Correlation-Id", correlationId);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write("{\"error\":\"" + error + "\",\"message\":\"" + message + "\"}");
        }
    }
}
