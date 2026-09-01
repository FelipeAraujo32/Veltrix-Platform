package com.gateway.gateway.Filter;

import java.time.Duration;
import java.time.Instant;
import org.slf4j.*;
import org.springframework.cloud.gateway.filter.*;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class AccessLoggingGlobalFilter implements GlobalFilter, Ordered {
    private static final Logger LOG=LoggerFactory.getLogger(AccessLoggingGlobalFilter.class);
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain){
        Instant started=Instant.now();
        return chain.filter(exchange).doFinally(signal->LOG.info("access correlationId={} method={} path={} status={} durationMs={} route={}",
                exchange.getRequest().getHeaders().getFirst(CorrelationIdGlobalFilter.HEADER),exchange.getRequest().getMethod(),exchange.getRequest().getURI().getPath(),
                exchange.getResponse().getStatusCode()==null?500:exchange.getResponse().getStatusCode().value(),Duration.between(started,Instant.now()).toMillis(),
                exchange.getAttribute("gatewayRouteId")));
    }
    public int getOrder(){return Ordered.LOWEST_PRECEDENCE;}
}
