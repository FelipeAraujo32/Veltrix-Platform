package br.com.veltrix.auth.domain;

import jakarta.persistence.*;
import java.util.HashSet;
import java.util.Set;

@Entity @Table(name="roles", schema="security", uniqueConstraints=@UniqueConstraint(name="uq_roles_tenant_name", columnNames={"tenant_id","name"}))
public class Role {
    @Id @GeneratedValue(strategy=GenerationType.IDENTITY) private Long id;
    @Column(nullable=false, length=80) private String name;
    @Column(name="tenant_id", length=80) private String tenantId; // NULL = template global da plataforma (somente leitura); preenchido = perfil custom do tenant
    @ManyToMany(fetch=FetchType.EAGER) @JoinTable(name="role_permissions", schema="security", joinColumns=@JoinColumn(name="role_id"), inverseJoinColumns=@JoinColumn(name="permission_id")) private Set<Permission> permissions=new HashSet<>();
    protected Role() {} public Role(String name){this.name=name;} public Role(String name,String tenantId){this.name=name;this.tenantId=tenantId;}
    public void addPermission(Permission permission){permissions.add(permission);}
    public void rename(String name){this.name=name;}
    public void replacePermissions(Set<Permission> newPermissions){permissions.clear();permissions.addAll(newPermissions);}
    public boolean isTemplate(){return tenantId==null;}
    public Long getId(){return id;} public String getName(){return name;} public String getTenantId(){return tenantId;} public Set<Permission> getPermissions(){return permissions;}
}
