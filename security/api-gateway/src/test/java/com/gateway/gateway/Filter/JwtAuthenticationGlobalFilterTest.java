package com.gateway.gateway.Filter;

import static org.mockito.Mockito.*;
import static org.assertj.core.api.Assertions.assertThat;

import com.gateway.gateway.Service.JwtService;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;
import org.springframework.security.oauth2.jwt.Jwt;
import java.time.Instant;

class JwtAuthenticationGlobalFilterTest{
    private static final List<String> PUBLIC_PATHS = List.of(
            "/api/v1/auth/**", "/.well-known/jwks.json", "/actuator/health", "/actuator/info",
            "/api/v1/ouvidoria/canais", "/api/v1/ouvidoria/manifestacoes",
            "/api/v1/ouvidoria/manifestacoes/*/anexos", "/api/v1/ouvidoria/manifestacoes/*/anexos/**");
    private final JwtService jwt=mock(JwtService.class);
    private final JwtAuthenticationGlobalFilter filter=new JwtAuthenticationGlobalFilter(jwt, new PublicPathMatcher(PUBLIC_PATHS));

    @Test
    void publicAttachmentDownloadDoesNotRequireJwt(){
        var exchange=MockServerWebExchange.from(MockServerHttpRequest.get("/api/v1/ouvidoria/manifestacoes/OUV-X/anexos/"+UUID.randomUUID()).header("X-Manifestation-Access-Code","secret").build());
        GatewayFilterChain chain=mock(GatewayFilterChain.class);when(chain.filter(exchange)).thenReturn(Mono.empty());

        filter.filter(exchange,chain).block();

        verify(chain).filter(exchange);verifyNoInteractions(jwt);
    }

    @Test
    void configurablePublicMetadataDoesNotRequireJwt(){
        var exchange=MockServerWebExchange.from(MockServerHttpRequest.get("/api/v1/ouvidoria/canais").build());
        GatewayFilterChain chain=mock(GatewayFilterChain.class);when(chain.filter(exchange)).thenReturn(Mono.empty());
        filter.filter(exchange,chain).block();
        verify(chain).filter(exchange);verifyNoInteractions(jwt);
    }

    @Test
    void dynamicTransitionsRemainProtected(){
        var exchange=MockServerWebExchange.from(MockServerHttpRequest.get("/api/v1/ouvidoria/manifestacoes/"+UUID.randomUUID()+"/transicoes").build());
        filter.filter(exchange,mock(GatewayFilterChain.class)).block();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void operationalManifestationRouteStillRequiresJwt(){
        var exchange=MockServerWebExchange.from(MockServerHttpRequest.get("/api/v1/ouvidoria/manifestacoes/"+UUID.randomUUID()).build());

        filter.filter(exchange,mock(GatewayFilterChain.class)).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void validJwtContinuesToDownstreamService(){
        var exchange=MockServerWebExchange.from(MockServerHttpRequest.get("/api/v1/me").header("Authorization","Bearer valid-token").build());
        GatewayFilterChain chain=mock(GatewayFilterChain.class);
        Jwt decoded=Jwt.withTokenValue("valid-token").header("alg","none").subject("42").issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build();
        when(jwt.decode("valid-token")).thenReturn(Mono.just(decoded));
        when(chain.filter(exchange)).thenReturn(Mono.empty());

        filter.filter(exchange,chain).block();

        verify(chain).filter(exchange);
    }

    @Test
    void invalidSignatureIsRejected(){
        var exchange=MockServerWebExchange.from(MockServerHttpRequest.get("/api/v1/me").header("Authorization","Bearer invalid-token").build());
        when(jwt.decode("invalid-token")).thenReturn(Mono.error(new IllegalArgumentException("invalid signature")));

        filter.filter(exchange,mock(GatewayFilterChain.class)).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }
}
