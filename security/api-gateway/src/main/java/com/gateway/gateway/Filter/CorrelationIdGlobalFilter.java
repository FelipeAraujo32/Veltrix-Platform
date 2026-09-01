package com.gateway.gateway.Filter;

import java.util.UUID;
import org.springframework.cloud.gateway.filter.*;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class CorrelationIdGlobalFilter implements GlobalFilter, Ordered {
    public static final String HEADER="X-Correlation-Id";
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String id=exchange.getRequest().getHeaders().getFirst(HEADER);
        if(id==null||id.isBlank()) id=UUID.randomUUID().toString();
        ServerHttpRequest request=exchange.getRequest().mutate().header(HEADER,id).build();
        ServerWebExchange enriched=exchange.mutate().request(request).build();
        enriched.getResponse().getHeaders().set(HEADER,id);
        return chain.filter(enriched);
    }
    public int getOrder(){return -200;}
}
