package br.com.veltrix.auth.infrastructure;

import br.com.veltrix.auth.domain.*;
import io.jsonwebtoken.Jwts;
import java.time.Instant;
import java.util.Date;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class JwtService {
    private final JwtKeyProvider keys; private final String issuer, audience; private final long ttl;
    public JwtService(JwtKeyProvider keys,@Value("${jwt.issuer}") String issuer,@Value("${jwt.audience}") String audience,@Value("${jwt.access-ttl-seconds}") long ttl){
        this.keys=keys;this.issuer=issuer;this.audience=audience;this.ttl=ttl;
    }
    public String create(User user){
        Instant now=Instant.now();
        var roles=user.getRoles().stream().map(Role::getName).collect(Collectors.toSet());
        var permissions=user.getRoles().stream().flatMap(r->r.getPermissions().stream()).map(Permission::getName).collect(Collectors.toSet());
        return Jwts.builder().header().keyId(keys.keyId()).and().subject(user.getId().toString()).issuer(issuer).audience().add(audience).and().issuedAt(Date.from(now)).expiration(Date.from(now.plusSeconds(ttl)))
                .claim("email",user.getEmail()).claim("name",user.getName()).claim("roles",roles).claim("permissions",permissions)
                .claim("contexts",user.getContextScopes()).claim("tenant_id",user.getTenantId()).claim("base_id",user.getActiveBaseId())
                .claim("access_version",user.getAccessVersion()).claim("token_version",user.getTokenVersion())
                .claim("password_change_required",user.isPasswordChangeRequired())
                .signWith(keys.privateKey(), Jwts.SIG.RS256).compact();
    }
    public io.jsonwebtoken.Claims parse(String token){return Jwts.parser().verifyWith(keys.publicKey()).requireIssuer(issuer).requireAudience(audience).build().parseSignedClaims(token).getPayload();}
}
