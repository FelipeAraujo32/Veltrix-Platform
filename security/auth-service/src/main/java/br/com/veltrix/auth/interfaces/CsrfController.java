package br.com.veltrix.auth.interfaces;

import br.com.veltrix.auth.infrastructure.SessionCsrfFilter;
import java.security.SecureRandom;
import java.util.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

@RestController @RequestMapping("/api/v1/auth")
public class CsrfController {
    private final SecureRandom random=new SecureRandom();private final boolean secure;
    public CsrfController(@Value("${security.cookies.secure:true}")boolean secure){this.secure=secure;}
    @GetMapping("/csrf") public ResponseEntity<TokenResponse> token(){byte[] bytes=new byte[32];random.nextBytes(bytes);String token=Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);ResponseCookie cookie=ResponseCookie.from(SessionCsrfFilter.COOKIE,token).httpOnly(true).secure(secure).sameSite("Strict").path("/api/v1/auth").maxAge(1800).build();return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE,cookie.toString()).cacheControl(CacheControl.noStore()).body(new TokenResponse(token));}
    public record TokenResponse(String token){}
}
