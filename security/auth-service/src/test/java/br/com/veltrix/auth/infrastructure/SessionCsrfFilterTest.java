package br.com.veltrix.auth.infrastructure;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.servlet.http.Cookie;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class SessionCsrfFilterTest {
    private final SessionCsrfFilter filter =
            new SessionCsrfFilter("https://portal.veltrix.example,https://ouvidoria.veltrix.example");

    @Test
    void allowsProtectedRequestWithTrustedOriginAndMatchingToken() throws Exception {
        var request = protectedRequest("https://portal.veltrix.example");
        request.setCookies(new Cookie(SessionCsrfFilter.COOKIE, "csrf-token"));
        request.addHeader(SessionCsrfFilter.HEADER, "csrf-token");
        var response = new MockHttpServletResponse();
        var invoked = new AtomicBoolean();

        filter.doFilter(request, response, (req, res) -> invoked.set(true));

        assertThat(invoked).isTrue();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void rejectsMismatchedToken() throws Exception {
        var request = protectedRequest("https://portal.veltrix.example");
        request.setCookies(new Cookie(SessionCsrfFilter.COOKIE, "expected"));
        request.addHeader(SessionCsrfFilter.HEADER, "forged");
        var response = new MockHttpServletResponse();

        filter.doFilter(request, response, (req, res) -> {});

        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void rejectsUntrustedOriginEvenWithMatchingToken() throws Exception {
        var request = protectedRequest("https://attacker.example");
        request.setCookies(new Cookie(SessionCsrfFilter.COOKIE, "csrf-token"));
        request.addHeader(SessionCsrfFilter.HEADER, "csrf-token");
        var response = new MockHttpServletResponse();

        filter.doFilter(request, response, (req, res) -> {});

        assertThat(response.getStatus()).isEqualTo(403);
    }

    private MockHttpServletRequest protectedRequest(String origin) {
        var request = new MockHttpServletRequest("POST", "/api/v1/auth/refresh");
        request.addHeader("Origin", origin);
        return request;
    }
}
