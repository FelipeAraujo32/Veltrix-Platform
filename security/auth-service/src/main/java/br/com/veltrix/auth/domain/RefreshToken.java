package br.com.veltrix.auth.domain;

import jakarta.persistence.*;
import java.time.Instant;

@Entity @Table(name="refresh_tokens", schema="security")
public class RefreshToken {
    @Id @GeneratedValue(strategy=GenerationType.IDENTITY) private Long id;
    @Column(name="token_hash", nullable=false, unique=true, length=64) private String tokenHash;
    @ManyToOne(fetch=FetchType.LAZY, optional=false) @JoinColumn(name="user_id") private User user;
    @Column(name="expires_at", nullable=false) private Instant expiresAt;
    @Column(name="revoked_at") private Instant revokedAt;
    protected RefreshToken() {}
    public RefreshToken(String hash, User user, Instant expiresAt){this.tokenHash=hash;this.user=user;this.expiresAt=expiresAt;}
    public User getUser(){return user;} public boolean isValid(Instant now){return revokedAt==null && expiresAt.isAfter(now);} public void revoke(Instant now){revokedAt=now;}
}
