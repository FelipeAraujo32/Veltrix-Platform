package com.gateway.gateway.Config;

import com.gateway.gateway.Filter.ClientIpResolver;
import com.gateway.gateway.Filter.PublicPathMatcher;
import com.gateway.gateway.Filter.ServiceKeyResolver;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties({GatewayProperties.class, RateLimitProperties.class})
public class RoutingConfig {

    @Bean
    ServiceKeyResolver serviceKeyResolver(GatewayProperties properties) {
        return new ServiceKeyResolver(properties.platformSegments());
    }

    @Bean
    PublicPathMatcher publicPathMatcher(GatewayProperties properties) {
        return new PublicPathMatcher(properties.publicPaths());
    }

    @Bean
    ClientIpResolver clientIpResolver(RateLimitProperties properties) {
        return new ClientIpResolver(properties.trustedProxies());
    }
}
