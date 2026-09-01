package br.com.veltrix.auth.interfaces;

import br.com.veltrix.auth.domain.*;
import br.com.veltrix.auth.infrastructure.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import org.springframework.http.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.beans.factory.annotation.Value;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.transaction.annotation.Transactional;

@RestController @RequestMapping("/api/v1")
public class AuthController {
    private static final Logger LOG = LoggerFactory.getLogger(AuthController.class);
    private static final String REFRESH_COOKIE="veltrix_refresh";
    private final UserRepository users; private final RefreshTokenRepository refreshTokens; private final PasswordEncoder passwords; private final JwtService jwt; private final SecureRandom random=new SecureRandom(); private final long refreshTtlSeconds;private final boolean secureCookie;private final LoginAttemptService loginAttempts;private final ClientIpResolver clientIp;private final String timingEqualizerHash;
    public AuthController(UserRepository users,RefreshTokenRepository refreshTokens,PasswordEncoder passwords,JwtService jwt,@Value("${jwt.refresh-ttl-seconds}") long refreshTtlSeconds,@Value("${security.cookies.secure:true}")boolean secureCookie,LoginAttemptService loginAttempts,ClientIpResolver clientIp){this.users=users;this.refreshTokens=refreshTokens;this.passwords=passwords;this.jwt=jwt;this.refreshTtlSeconds=refreshTtlSeconds;this.secureCookie=secureCookie;this.loginAttempts=loginAttempts;this.clientIp=clientIp;this.timingEqualizerHash=passwords.encode("veltrix-timing-equalizer-"+random.nextLong());}
    @PostMapping("/auth/login") public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request,HttpServletRequest http){
        String ip=clientIp.resolve(http);
        long retryAfter=loginAttempts.blockedForSeconds(request.email(),ip);
        if(retryAfter>0){LOG.warn("Login bloqueado por lockout: ip={}",ip);throw new LockedException(retryAfter);}
        User user=users.findByEmailIgnoreCase(request.email()).filter(u->u.getStatus()==UserStatus.ACTIVE).orElse(null);
        boolean valid=user!=null&&passwords.matches(request.password(),user.getPasswordHash());
        if(user==null)passwords.matches(request.password(),timingEqualizerHash); // custo BCrypt também no ramo "conta inexistente": sem oráculo de timing p/ enumeração
        if(!valid){loginAttempts.onFailure(request.email(),ip);throw new UnauthorizedException();}
        loginAttempts.onSuccess(request.email(),ip);
        Issued issued=issue(user);return tokens(issued);
    }
    @PostMapping("/auth/refresh") @Transactional public ResponseEntity<TokenResponse> refresh(@CookieValue(name=REFRESH_COOKIE,required=false)String refreshCookie){
        String raw=refreshCookie;if(raw==null||raw.isBlank())throw new UnauthorizedException();
        String hash=hash(raw); RefreshToken old=refreshTokens.findByTokenHash(hash).filter(t->t.isValid(Instant.now())).orElseThrow(()->new UnauthorizedException());
        old.revoke(Instant.now()); refreshTokens.save(old);
        if(old.getUser().getStatus()!=UserStatus.ACTIVE)throw new UnauthorizedException(); // fail-closed: usuário desativado pela gestão de equipe não renova sessão
        return tokens(issue(old.getUser()));
    }
    @PostMapping("/auth/logout") @Transactional public ResponseEntity<Void> logout(@CookieValue(name=REFRESH_COOKIE,required=false)String refreshCookie){String raw=refreshCookie;if(raw!=null&&!raw.isBlank())refreshTokens.findByTokenHash(hash(raw)).ifPresent(t->{t.revoke(Instant.now());refreshTokens.save(t);});return ResponseEntity.noContent().header(HttpHeaders.SET_COOKIE,cookie("",0).toString()).cacheControl(CacheControl.noStore()).build();}
    @GetMapping("/me") public MeResponse me(@AuthenticationPrincipal Jwt token){
        LOG.info("/me autenticado: subject={}, email={}", token.getSubject(), token.getClaimAsString("email"));
        return new MeResponse(Long.valueOf(token.getSubject()),token.getClaimAsString("email"),token.getClaimAsString("name"),Boolean.TRUE.equals(token.getClaimAsBoolean("password_change_required")));
    }
    // Fica em /me/password (fora de /auth/**): exige Bearer autenticado (anyRequest().authenticated())
    // e não passa pelo fluxo de cookie CSRF, que cobre apenas login/refresh/logout.
    @PostMapping("/me/password") @ResponseStatus(HttpStatus.NO_CONTENT) @Transactional
    public void changePassword(@Valid @RequestBody ChangePasswordRequest request,@AuthenticationPrincipal Jwt token){
        User user=users.findById(Long.valueOf(token.getSubject())).filter(u->u.getStatus()==UserStatus.ACTIVE).orElseThrow(UnauthorizedException::new);
        if(!passwords.matches(request.currentPassword(),user.getPasswordHash()))throw new BusinessException("INVALID_CURRENT_PASSWORD","Senha atual incorreta");
        user.changePassword(passwords.encode(request.newPassword())); users.save(user);
        refreshTokens.revokeAllByUserId(user.getId(),Instant.now()); // "sair de todos os dispositivos": sessões antigas morrem no próximo refresh (janela do access token <=15min é o tradeoff aceito)
        LOG.info("Senha alterada pelo próprio usuário: id={}",user.getId());
    }
    private Issued issue(User user){
        String raw=generateToken(); refreshTokens.save(new RefreshToken(hash(raw),user,Instant.now().plusSeconds(refreshTtlSeconds))); return new Issued(jwt.create(user),raw,user.isPasswordChangeRequired());
    }
    private ResponseEntity<TokenResponse> tokens(Issued issued){return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE,cookie(issued.refreshToken(),refreshTtlSeconds).toString()).cacheControl(CacheControl.noStore()).body(new TokenResponse(issued.accessToken(),"Bearer",issued.passwordChangeRequired()));}
    private ResponseCookie cookie(String value,long maxAge){return ResponseCookie.from(REFRESH_COOKIE,value).httpOnly(true).secure(secureCookie).sameSite("Strict").path("/api/v1/auth").maxAge(maxAge).build();}
    private String generateToken(){byte[] bytes=new byte[48];random.nextBytes(bytes);return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);}
    static String hash(String value){try{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));}catch(Exception e){throw new IllegalStateException(e);}}
    public record LoginRequest(@NotBlank @Email String email,@NotBlank String password){}
    public record TokenResponse(String accessToken,String tokenType,boolean passwordChangeRequired){}
    private record Issued(String accessToken,String refreshToken,boolean passwordChangeRequired){}
    public record MeResponse(Long id,String email,String name,boolean passwordChangeRequired){}
    public record ChangePasswordRequest(@NotBlank String currentPassword,@NotBlank @Size(min=10,max=128) String newPassword){}
    static class UnauthorizedException extends RuntimeException{}
    static class LockedException extends RuntimeException{final long retryAfterSeconds;LockedException(long retryAfterSeconds){this.retryAfterSeconds=retryAfterSeconds;}}
}
