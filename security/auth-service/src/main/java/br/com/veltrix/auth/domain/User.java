package br.com.veltrix.auth.domain;

import jakarta.persistence.*;
import java.util.HashSet;
import java.util.Set;

@Entity @Table(name="users", schema="security")
public class User {
    @Id @GeneratedValue(strategy=GenerationType.IDENTITY) private Long id;
    @Column(nullable=false, unique=true, length=255) private String email;
    @Column(name="password_hash", nullable=false, length=255) private String passwordHash;
    @Column(nullable=false, length=120) private String name;
    @Enumerated(EnumType.STRING) @Column(nullable=false, length=20) private UserStatus status = UserStatus.ACTIVE;
    @Column(name="tenant_id",nullable=false,length=80) private String tenantId="DEFAULT";
    @Column(name="active_base_id",length=80) private String activeBaseId;
    @Column(name="access_version",nullable=false) private long accessVersion;
    @Column(name="token_version",nullable=false) private long tokenVersion;
    @Column(name="password_change_required",nullable=false) private boolean passwordChangeRequired;
    @ManyToMany(fetch=FetchType.EAGER) @JoinTable(name="user_roles", schema="security", joinColumns=@JoinColumn(name="user_id"), inverseJoinColumns=@JoinColumn(name="role_id"))
    private Set<Role> roles = new HashSet<>();
    @ElementCollection(fetch=FetchType.EAGER)
    @CollectionTable(name="user_context_scopes", schema="security", joinColumns=@JoinColumn(name="user_id"))
    @Column(name="context_code", nullable=false, length=80)
    private Set<String> contextScopes = new HashSet<>();
    protected User() {}
    public User(String email, String passwordHash, String name, UserStatus status) { this.email=email; this.passwordHash=passwordHash; this.name=name; this.status=status; }
    public void addRole(Role role) { roles.add(role); }
    public void addContextScope(String contextCode) { contextScopes.add(contextCode); }
    public void replaceContextScopes(Set<String> contextCodes) { contextScopes.clear(); contextScopes.addAll(contextCodes); }
    public void changeAccessContext(String tenantId,String baseId){if(tenantId==null||tenantId.isBlank())throw new IllegalArgumentException("tenantId is required");this.tenantId=tenantId;this.activeBaseId=baseId;this.accessVersion++;}
    public void touchAccessVersion(){this.accessVersion++;}
    public void replaceRoles(Set<Role> newRoles){roles.clear();roles.addAll(newRoles);}
    public void changeStatus(UserStatus status){this.status=status;this.tokenVersion++;}
    public void requirePasswordChange(){this.passwordChangeRequired=true;}
    public void issueTemporaryPassword(String passwordHash){this.passwordHash=passwordHash;this.passwordChangeRequired=true;this.tokenVersion++;}
    public void changePassword(String passwordHash){this.passwordHash=passwordHash;this.passwordChangeRequired=false;this.tokenVersion++;}
    public Long getId(){return id;} public String getEmail(){return email;} public String getPasswordHash(){return passwordHash;}
    public String getName(){return name;} public UserStatus getStatus(){return status;} public Set<Role> getRoles(){return roles;} public Set<String> getContextScopes(){return contextScopes;}
    public String getTenantId(){return tenantId;} public String getActiveBaseId(){return activeBaseId;} public long getAccessVersion(){return accessVersion;} public long getTokenVersion(){return tokenVersion;}
    public boolean isPasswordChangeRequired(){return passwordChangeRequired;}
}
