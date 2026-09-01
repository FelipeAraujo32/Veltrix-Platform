package com.gateway.gateway.Controller;

import java.util.Map;
import java.util.UUID;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ServerWebExchange;

@RestController
public class FallbackController {
    @GetMapping("/fallback/service-unavailable")
    public ResponseEntity<Map<String,String>> unavailable(ServerWebExchange exchange) {
        String correlationId = exchange.getRequest().getHeaders().getFirst("X-Correlation-Id");
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(Map.of(
                "error", "SERVICE_UNAVAILABLE",
                "message", "Serviço temporariamente indisponível",
                "correlationId", correlationId == null ? UUID.randomUUID().toString() : correlationId));
    }
}
