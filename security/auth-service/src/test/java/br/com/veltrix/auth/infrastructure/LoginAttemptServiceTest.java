package br.com.veltrix.auth.infrastructure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.data.redis.core.script.RedisScript;

class LoginAttemptServiceTest {

    private StringRedisTemplate redis;
    @SuppressWarnings("unchecked")
    private ValueOperations<String, String> valueOps = mock(ValueOperations.class);
    private LoginAttemptService service;
    /** Per-key counter values returned by the (mocked) atomic INCR script. */
    private final Map<String, Long> counters = new HashMap<>();

    @BeforeEach
    void setUp() {
        redis = mock(StringRedisTemplate.class);
        when(redis.opsForValue()).thenReturn(valueOps);
        when(redis.execute(ArgumentMatchers.<RedisScript<Long>>any(), anyList(), any()))
                .thenAnswer(invocation -> {
                    List<String> keys = invocation.getArgument(1);
                    if (keys == null || keys.isEmpty()) return 1L; // matcher placeholder during re-stubbing
                    return counters.getOrDefault(keys.get(0), 1L);
                });
        // default: no keys exist
        when(redis.getExpire(anyString(), eq(TimeUnit.SECONDS))).thenReturn(-2L);
        // pair: 5 attempts, 1m base, 15m cap; account: 30 attempts, 5m fixed, 10m window
        service = new LoginAttemptService(redis, 5, Duration.ofMinutes(1), Duration.ofMinutes(15), Duration.ofMinutes(15),
                30, Duration.ofMinutes(5), Duration.ofMinutes(10));
    }

    @Test
    void notBlockedWhenNoBlockKeys() {
        assertThat(service.blockedForSeconds("user@x.com", "1.2.3.4")).isZero();
    }

    @Test
    void blockedReturnsRemainingPairTtlForRetryAfter() {
        when(redis.getExpire("login:block:user@x.com|1.2.3.4", TimeUnit.SECONDS)).thenReturn(42L);
        assertThat(service.blockedForSeconds("USER@x.com", "1.2.3.4")).isEqualTo(42); // email normalized
    }

    @Test
    void pairBlockFromAttackerIpDoesNotBlockVictimFromHerOwnIp() {
        // Attacker at 6.6.6.6 got the pair blocked; the victim logging in from 9.9.9.9 must NOT be blocked.
        when(redis.getExpire("login:block:victim@x.com|6.6.6.6", TimeUnit.SECONDS)).thenReturn(120L);
        assertThat(service.blockedForSeconds("victim@x.com", "9.9.9.9")).isZero();
    }

    @Test
    void accountLevelBlockAppliesFromAnyIp() {
        // Distributed/spoofed attack tripped the account-level threshold: blocked regardless of IP.
        when(redis.getExpire("login:acctblock:victim@x.com", TimeUnit.SECONDS)).thenReturn(200L);
        assertThat(service.blockedForSeconds("victim@x.com", "9.9.9.9")).isEqualTo(200);
        assertThat(service.blockedForSeconds("victim@x.com", "1.1.1.1")).isEqualTo(200);
    }

    @Test
    void isBlockedFailsOpenOnRedisError() {
        when(redis.getExpire(anyString(), eq(TimeUnit.SECONDS))).thenThrow(new RuntimeException("redis down"));
        assertThat(service.blockedForSeconds("user@x.com", "1.2.3.4")).isZero();
    }

    @Test
    void earlyFailuresDoNotBlock() {
        counters.put("login:fail:user@x.com|1.2.3.4", 1L);
        counters.put("login:acctfail:user@x.com", 1L);
        service.onFailure("user@x.com", "1.2.3.4");
        verify(valueOps, never()).set(anyString(), anyString(), anyLong(), any());
    }

    @Test
    void reachingPairThresholdAppliesProgressiveBlockAndResetsFailCounter() {
        counters.put("login:fail:user@x.com|1.2.3.4", 5L);
        counters.put("login:cycle:user@x.com|1.2.3.4", 1L);
        service.onFailure("user@x.com", "1.2.3.4");
        // base block 60s on first cycle
        verify(valueOps).set(eq("login:block:user@x.com|1.2.3.4"), eq("1"), eq(60L), eq(TimeUnit.SECONDS));
        verify(redis).delete("login:fail:user@x.com|1.2.3.4");
    }

    @Test
    void constantIpScenarioDifferentAccountsUseDistinctPairKeys() {
        // Behind a misconfigured proxy chain every client shows the same IP: failures on account A must
        // not increment account B's keys (no cross-account lock from a shared IP).
        counters.put("login:fail:a@x.com|10.0.0.2", 5L);
        counters.put("login:cycle:a@x.com|10.0.0.2", 1L);
        service.onFailure("a@x.com", "10.0.0.2");
        verify(valueOps).set(eq("login:block:a@x.com|10.0.0.2"), anyString(), anyLong(), eq(TimeUnit.SECONDS));
        verify(valueOps, never()).set(startsWith("login:block:b@x.com"), anyString(), anyLong(), any());
        assertThat(service.blockedForSeconds("b@x.com", "10.0.0.2")).isZero();
    }

    @Test
    void accountThresholdAppliesShortFixedBlock() {
        counters.put("login:fail:victim@x.com|7.7.7.7", 1L);
        counters.put("login:acctfail:victim@x.com", 30L);
        service.onFailure("victim@x.com", "7.7.7.7");
        // fixed 5m (300s) block, NON progressive: bounded victim-DoS, still stops distributed brute force
        verify(valueOps).set(eq("login:acctblock:victim@x.com"), eq("1"), eq(300L), eq(TimeUnit.SECONDS));
        verify(redis).delete("login:acctfail:victim@x.com");
    }

    @Test
    void successClearsAllState() {
        service.onSuccess("user@x.com", "1.2.3.4");
        verify(redis).delete("login:fail:user@x.com|1.2.3.4");
        verify(redis).delete("login:block:user@x.com|1.2.3.4");
        verify(redis).delete("login:cycle:user@x.com|1.2.3.4");
        verify(redis).delete("login:acctfail:user@x.com");
        verify(redis).delete("login:acctblock:user@x.com");
    }

    @Test
    void onFailureFailsOpenOnRedisError() {
        doThrow(new RuntimeException("redis down"))
                .when(redis).execute(ArgumentMatchers.<RedisScript<Long>>any(), anyList(), any());
        // must not throw
        service.onFailure("user@x.com", "1.2.3.4");
    }

    @Test
    void backoffGrowsExponentiallyAndCaps() {
        // base 1m, cap 15m
        assertThat(service.backoff(1)).isEqualTo(Duration.ofMinutes(1));   // 1m * 2^0
        assertThat(service.backoff(2)).isEqualTo(Duration.ofMinutes(2));   // 1m * 2^1
        assertThat(service.backoff(3)).isEqualTo(Duration.ofMinutes(4));   // 1m * 2^2
        assertThat(service.backoff(4)).isEqualTo(Duration.ofMinutes(8));   // 1m * 2^3
        assertThat(service.backoff(5)).isEqualTo(Duration.ofMinutes(15));  // 16m capped to 15m
        assertThat(service.backoff(50)).isEqualTo(Duration.ofMinutes(15)); // capped, no overflow
    }
}
