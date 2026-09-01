package br.com.veltrix.auth.infrastructure;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Service;

/**
 * Progressive login lockout backed by Redis (closes L4 brute-force at the service layer, complementing
 * the gateway per-IP rate limit). Two independent keys:
 *
 * <ul>
 * <li><b>account+IP</b> ({@code maxAttempts}, default 5): fast, progressive block (exponential backoff,
 * capped). With trusted proxies configured this throttles a single attacker without touching the victim
 * on her own IP.</li>
 * <li><b>account only</b> ({@code accountMaxAttempts}, default 30, short window): a much higher threshold
 * with a fixed, short, NON-progressive block. It catches distributed/spoofed brute-force that rotates IPs
 * (where the pair key never accumulates), while keeping victim-lockout expensive (30 failures per cycle)
 * and bounded (short fixed block, no escalation).</li>
 * </ul>
 *
 * A successful login resets all counters. Callers must translate a block into a uniform response (429)
 * that does not leak account existence, and must count a failure regardless of whether the account exists.
 *
 * <p>Counters use an atomic INCR+EXPIRE Lua script (no TTL-less keys on partial failure). Fail-open: if
 * Redis is unavailable, authentication proceeds unthrottled rather than locking every user out — the
 * gateway rate limit remains as a second layer, and a short Redis command timeout keeps a slow Redis from
 * adding latency to every login.
 */
@Service
public class LoginAttemptService {
    private static final Logger LOG = LoggerFactory.getLogger(LoginAttemptService.class);
    private static final String FAIL_PREFIX = "login:fail:";
    private static final String BLOCK_PREFIX = "login:block:";
    private static final String CYCLE_PREFIX = "login:cycle:";
    private static final String ACCT_FAIL_PREFIX = "login:acctfail:";
    private static final String ACCT_BLOCK_PREFIX = "login:acctblock:";
    /** Atomic counter: INCR and, on first hit only, EXPIRE — one round-trip, no TTL-less keys. */
    private static final RedisScript<Long> INCR_TTL_FIRST = RedisScript.of(
            "local c = redis.call('INCR', KEYS[1]) if c == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end return c",
            Long.class);
    /** Atomic counter that refreshes the TTL on every hit (used for the escalation-cycle memory). */
    private static final RedisScript<Long> INCR_TTL_ALWAYS = RedisScript.of(
            "local c = redis.call('INCR', KEYS[1]) redis.call('EXPIRE', KEYS[1], ARGV[1]) return c",
            Long.class);

    private final StringRedisTemplate redis;
    private final int maxAttempts;
    private final Duration baseBlock;
    private final Duration maxBlock;
    private final Duration failWindow;
    private final int accountMaxAttempts;
    private final Duration accountBlock;
    private final Duration accountFailWindow;

    public LoginAttemptService(
            StringRedisTemplate redis,
            @Value("${security.login-lockout.max-attempts:5}") int maxAttempts,
            @Value("${security.login-lockout.base-block:1m}") Duration baseBlock,
            @Value("${security.login-lockout.max-block:15m}") Duration maxBlock,
            @Value("${security.login-lockout.fail-window:15m}") Duration failWindow,
            @Value("${security.login-lockout.account-max-attempts:30}") int accountMaxAttempts,
            @Value("${security.login-lockout.account-block:5m}") Duration accountBlock,
            @Value("${security.login-lockout.account-fail-window:10m}") Duration accountFailWindow) {
        this.redis = redis;
        this.maxAttempts = maxAttempts <= 0 ? 5 : maxAttempts;
        this.baseBlock = baseBlock == null ? Duration.ofMinutes(1) : baseBlock;
        this.maxBlock = maxBlock == null ? Duration.ofMinutes(15) : maxBlock;
        this.failWindow = failWindow == null ? Duration.ofMinutes(15) : failWindow;
        this.accountMaxAttempts = accountMaxAttempts <= 0 ? 30 : accountMaxAttempts;
        this.accountBlock = accountBlock == null ? Duration.ofMinutes(5) : accountBlock;
        this.accountFailWindow = accountFailWindow == null ? Duration.ofMinutes(10) : accountFailWindow;
    }

    /**
     * Remaining block time in seconds for this account+IP pair or the account as a whole
     * (whichever is longer); {@code 0} when not blocked. Fail-open on Redis errors.
     */
    public long blockedForSeconds(String email, String ip) {
        try {
            long pair = remainingTtl(BLOCK_PREFIX + pairId(email, ip));
            long account = remainingTtl(ACCT_BLOCK_PREFIX + accountId(email));
            return Math.max(pair, account);
        } catch (RuntimeException e) {
            LOG.error("Login lockout check unavailable, allowing attempt type={}", e.getClass().getSimpleName());
            return 0;
        }
    }

    /** Records a failed attempt on both keys; applies blocks when the thresholds are reached. */
    public void onFailure(String email, String ip) {
        String pair = pairId(email, ip);
        String account = accountId(email);
        try {
            Long pairFails = increment(FAIL_PREFIX + pair, failWindow, false);
            if (pairFails != null && pairFails >= maxAttempts) {
                applyPairBlock(pair);
                redis.delete(FAIL_PREFIX + pair);
            }
            Long accountFails = increment(ACCT_FAIL_PREFIX + account, accountFailWindow, false);
            if (accountFails != null && accountFails >= accountMaxAttempts) {
                redis.opsForValue().set(ACCT_BLOCK_PREFIX + account, "1", accountBlock.toSeconds(), TimeUnit.SECONDS);
                redis.delete(ACCT_FAIL_PREFIX + account);
                LOG.warn("Account-level login lockout applied accountHash={} blockSeconds={}",
                        account.hashCode(), accountBlock.toSeconds());
            }
        } catch (RuntimeException e) {
            LOG.error("Login lockout record failed type={}", e.getClass().getSimpleName());
        }
    }

    /** Clears failure/lock state after a successful login. */
    public void onSuccess(String email, String ip) {
        String pair = pairId(email, ip);
        String account = accountId(email);
        try {
            redis.delete(FAIL_PREFIX + pair);
            redis.delete(BLOCK_PREFIX + pair);
            redis.delete(CYCLE_PREFIX + pair);
            redis.delete(ACCT_FAIL_PREFIX + account);
            redis.delete(ACCT_BLOCK_PREFIX + account);
        } catch (RuntimeException e) {
            LOG.error("Login lockout reset failed type={}", e.getClass().getSimpleName());
        }
    }

    private void applyPairBlock(String pair) {
        // Cycle memory outlives the block so repeat offenders keep escalating.
        Long cycle = increment(CYCLE_PREFIX + pair, maxBlock.multipliedBy(4), true);
        long cycleCount = cycle == null ? 1L : cycle;
        Duration block = backoff(cycleCount);
        redis.opsForValue().set(BLOCK_PREFIX + pair, "1", block.toSeconds(), TimeUnit.SECONDS);
        LOG.warn("Login temporarily locked idHash={} cycle={} blockSeconds={}", pair.hashCode(), cycleCount, block.toSeconds());
    }

    private Long increment(String key, Duration ttl, boolean refreshTtl) {
        return redis.execute(refreshTtl ? INCR_TTL_ALWAYS : INCR_TTL_FIRST,
                List.of(key), String.valueOf(ttl.toSeconds()));
    }

    private long remainingTtl(String key) {
        Long ttl = redis.getExpire(key, TimeUnit.SECONDS);
        if (ttl == null || ttl == -2) return 0;              // key absent: not blocked
        if (ttl == -1) return baseBlock.toSeconds();          // key without TTL (should not happen): treat as blocked
        return Math.max(0, ttl);
    }

    /** Exponential backoff: base * 2^(cycle-1), capped at maxBlock. */
    Duration backoff(long cycle) {
        long factor = 1L << Math.min(cycle - 1, 20); // guard against overflow
        Duration candidate = baseBlock.multipliedBy(factor);
        return candidate.compareTo(maxBlock) > 0 ? maxBlock : candidate;
    }

    private String pairId(String email, String ip) {
        String normalizedIp = ip == null || ip.isBlank() ? "unknown" : ip;
        return accountId(email) + "|" + normalizedIp;
    }

    private String accountId(String email) {
        return email == null ? "" : email.trim().toLowerCase();
    }
}
