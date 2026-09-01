package com.gateway.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.gateway.filter.headers.RemoveXForwardedHeadersFilter;
import org.springframework.cloud.gateway.filter.headers.XForwardedHeadersFilter;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest
@ActiveProfiles("test")
class GatewayApplicationTests {

	@Autowired
	private ApplicationContext context;

	@Test
	void contextLoads() {
	}

	/**
	 * Without {@code spring.cloud.gateway.server.webflux.trusted-proxies}, Spring Cloud Gateway 5
	 * registers RemoveXForwardedHeadersFilter and STRIPS X-Forwarded-* before proxying — the LB's
	 * https scheme would never reach downstream services. This locks in the relay behavior.
	 */
	@Test
	void trustedProxiesConfigRelaysForwardedHeadersDownstream() {
		assertThat(context.getBeanNamesForType(XForwardedHeadersFilter.class)).isNotEmpty();
		assertThat(context.getBeanNamesForType(RemoveXForwardedHeadersFilter.class)).isEmpty();
	}

}
