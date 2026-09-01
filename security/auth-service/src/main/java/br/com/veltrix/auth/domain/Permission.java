package br.com.veltrix.auth.domain;

import jakarta.persistence.*;

@Entity @Table(name="permissions", schema="security")
public class Permission {
    @Id @GeneratedValue(strategy=GenerationType.IDENTITY) private Long id;
    @Column(nullable=false, unique=true, length=120) private String name;
    @Column(name="tenant_assignable", nullable=false) private boolean tenantAssignable; // fail-closed: só permissão marcada pode ser concedida pela gestão de equipe do tenant
    protected Permission() {} public Permission(String name){this.name=name;} public Permission(String name,boolean tenantAssignable){this.name=name;this.tenantAssignable=tenantAssignable;}
    public String getName(){return name;} public boolean isTenantAssignable(){return tenantAssignable;}
}
