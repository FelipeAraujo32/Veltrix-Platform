package br.com.veltrix.auth.interfaces;

import br.com.veltrix.auth.domain.*;
import br.com.veltrix.auth.infrastructure.*;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/team")
@PreAuthorize("hasAuthority('ACCOUNT_TEAM_MANAGE')")
public class TeamController {
    private static final Logger LOG=LoggerFactory.getLogger(TeamController.class);
    private static final String TEAM_MANAGE_PERMISSION="ACCOUNT_TEAM_MANAGE";
    // Sem caracteres ambíguos (0/O, 1/l/I): a senha temporária é digitada pelo novo usuário.
    private static final String PASSWORD_ALPHABET="ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%*-_";
    private static final int PASSWORD_LENGTH=20;
    private final UserRepository users; private final RoleRepository roles; private final PermissionRepository permissions;
    private final RefreshTokenRepository refreshTokens; private final PasswordEncoder passwords; private final SecureRandom random=new SecureRandom();

    public TeamController(UserRepository users,RoleRepository roles,PermissionRepository permissions,RefreshTokenRepository refreshTokens,PasswordEncoder passwords){this.users=users;this.roles=roles;this.permissions=permissions;this.refreshTokens=refreshTokens;this.passwords=passwords;}

    @GetMapping("/users") public List<TeamUserResponse> listUsers(@AuthenticationPrincipal Jwt token){
        return users.findByTenantIdOrderByNameAsc(tenant(token)).stream().map(this::toUser).toList();
    }

    @PostMapping("/users") @ResponseStatus(HttpStatus.CREATED) @Transactional
    public CreatedUserResponse createUser(@Valid @RequestBody CreateUserRequest request,@AuthenticationPrincipal Jwt token){
        String tenant=tenant(token); String email=request.email().trim();
        users.findByEmailIgnoreCase(email).ifPresent(existing->{throw new BusinessException("EMAIL_IN_USE","Já existe um usuário com este e-mail");});
        Set<Role> assigned=visibleRoles(request.roleIds(),tenant);
        String temporaryPassword=generateTemporaryPassword();
        User user=new User(email,passwords.encode(temporaryPassword),request.name().trim(),UserStatus.ACTIVE);
        user.changeAccessContext(tenant,null); user.requirePasswordChange(); assigned.forEach(user::addRole);
        users.save(user);
        LOG.info("Usuário criado pela gestão de equipe: tenant={}, targetUserId={}, roles={}",tenant,user.getId(),assigned.size());
        return new CreatedUserResponse(user.getId(),user.getEmail(),user.getName(),temporaryPassword);
    }

    @PatchMapping("/users/{id}") @Transactional
    public TeamUserResponse updateUser(@PathVariable Long id,@Valid @RequestBody UpdateUserRequest request,@AuthenticationPrincipal Jwt token){
        String tenant=tenant(token); Long callerId=Long.valueOf(token.getSubject());
        User user=users.findByIdAndTenantId(id,tenant).orElseThrow(()->new BusinessException("USER_NOT_FOUND","Usuário não encontrado"));
        if(request.status()!=null){
            UserStatus status=UserStatus.valueOf(request.status());
            if(user.getId().equals(callerId)&&status!=UserStatus.ACTIVE)throw new BusinessException("SELF_DEACTIVATION","Você não pode desativar a própria conta");
            user.changeStatus(status);
            if(status!=UserStatus.ACTIVE)refreshTokens.revokeAllByUserId(user.getId(),Instant.now()); // desativação mata a sessão de verdade: sem refresh, o acesso expira em <=15min
        }
        if(request.roleIds()!=null){
            Set<Role> assigned=visibleRoles(request.roleIds(),tenant);
            boolean keepsTeamManage=assigned.stream().flatMap(r->r.getPermissions().stream()).anyMatch(p->TEAM_MANAGE_PERMISSION.equals(p.getName()));
            if(user.getId().equals(callerId)&&!keepsTeamManage)throw new BusinessException("SELF_TEAM_MANAGE_REMOVAL","Você não pode remover sua própria permissão de gestão da equipe");
            user.replaceRoles(assigned); user.touchAccessVersion();
        }
        users.save(user);
        LOG.info("Usuário atualizado pela gestão de equipe: tenant={}, targetUserId={}",tenant,id);
        return toUser(user);
    }

    @PostMapping("/users/{id}/reset-password") @Transactional
    public TemporaryPasswordResponse resetPassword(@PathVariable Long id,@AuthenticationPrincipal Jwt token){
        String tenant=tenant(token);
        User user=users.findByIdAndTenantId(id,tenant).orElseThrow(()->new BusinessException("USER_NOT_FOUND","Usuário não encontrado"));
        String temporaryPassword=generateTemporaryPassword();
        user.issueTemporaryPassword(passwords.encode(temporaryPassword));
        users.save(user);
        refreshTokens.revokeAllByUserId(user.getId(),Instant.now()); // reset administrativo derruba sessões existentes no próximo refresh
        LOG.info("Senha temporária emitida: tenant={}, targetUserId={}",tenant,id);
        return new TemporaryPasswordResponse(temporaryPassword);
    }

    @GetMapping("/roles") public List<RoleResponse> listRoles(@AuthenticationPrincipal Jwt token){
        return roles.findByTenantIdOrTenantIdIsNull(tenant(token)).stream()
                .sorted(Comparator.comparing(Role::isTemplate).reversed().thenComparing(Role::getName,String.CASE_INSENSITIVE_ORDER)).map(this::toRole).toList();
    }

    @PostMapping("/roles") @ResponseStatus(HttpStatus.CREATED) @Transactional
    public RoleResponse createRole(@Valid @RequestBody CreateRoleRequest request,@AuthenticationPrincipal Jwt token){
        String tenant=tenant(token); String name=request.name().trim();
        rejectReservedName(name);
        if(roles.existsByNameIgnoreCaseAndTenantId(name,tenant)||roles.existsByNameIgnoreCaseAndTenantIdIsNull(name))throw new BusinessException("ROLE_NAME_IN_USE","Já existe um perfil com este nome");
        Role role=new Role(name,tenant);
        resolvePermissions(request.permissionNames()).forEach(role::addPermission);
        roles.save(role);
        LOG.info("Perfil custom criado: tenant={}, roleId={}",tenant,role.getId());
        return toRole(role);
    }

    @PatchMapping("/roles/{id}") @Transactional
    public RoleResponse updateRole(@PathVariable Long id,@Valid @RequestBody UpdateRoleRequest request,@AuthenticationPrincipal Jwt token){
        String tenant=tenant(token);
        Role role=roles.findById(id).orElseThrow(()->new BusinessException("ROLE_NOT_FOUND","Perfil não encontrado"));
        if(role.isTemplate())throw new BusinessException("TEMPLATE_ROLE_READONLY","Perfis padrão da plataforma são somente leitura");
        if(!tenant.equals(role.getTenantId()))throw new BusinessException("ROLE_NOT_FOUND","Perfil não encontrado"); // 404, não 403: não vaza existência cross-tenant
        if(request.name()!=null){
            String name=request.name().trim();
            if(name.isBlank())throw new BusinessException("VALIDATION_ERROR","Nome do perfil não pode ser vazio");
            rejectReservedName(name);
            if(!name.equalsIgnoreCase(role.getName())&&(roles.existsByNameIgnoreCaseAndTenantId(name,tenant)||roles.existsByNameIgnoreCaseAndTenantIdIsNull(name)))throw new BusinessException("ROLE_NAME_IN_USE","Já existe um perfil com este nome");
            role.rename(name);
        }
        if(request.permissionNames()!=null)role.replacePermissions(resolvePermissions(request.permissionNames()));
        roles.save(role);
        LOG.info("Perfil custom atualizado: tenant={}, roleId={}",tenant,id);
        return toRole(role);
    }

    @GetMapping("/permissions") public List<String> listPermissions(){
        // Só o catálogo tenant-grade: permissões de plataforma nem sequer são divulgadas para a conta.
        return permissions.findByTenantAssignableTrue().stream().map(Permission::getName).sorted().toList();
    }

    private String tenant(Jwt token){String tenant=token.getClaimAsString("tenant_id");if(tenant==null||tenant.isBlank())throw new BusinessException("TENANT_REQUIRED","Contexto de tenant ausente no token");return tenant;}
    private Set<Role> visibleRoles(Set<Long> roleIds,String tenant){
        List<Role> found=roles.findAllById(roleIds);
        if(found.size()!=roleIds.size()||found.stream().anyMatch(r->r.getTenantId()!=null&&!r.getTenantId().equals(tenant)))throw new BusinessException("ROLE_NOT_FOUND","Perfil não encontrado");
        return new HashSet<>(found);
    }
    private Set<Permission> resolvePermissions(Set<String> names){
        Set<Permission> resolved=new HashSet<>();
        if(names.isEmpty())throw new BusinessException("VALIDATION_ERROR","Informe ao menos uma permissão");
        names.forEach(name->{
            Permission permission=permissions.findByName(name.trim().toUpperCase()).orElseThrow(()->new BusinessException("PERMISSION_NOT_FOUND","Permissão não encontrada"));
            // Fail-closed: permissão de plataforma (tenant_assignable=0) nunca entra em perfil de tenant.
            if(!permission.isTenantAssignable())throw new BusinessException("PERMISSION_NOT_ASSIGNABLE","Permissão não disponível para perfis da conta");
            resolved.add(permission);
        });
        return resolved;
    }
    private void rejectReservedName(String name){if("ADMIN".equalsIgnoreCase(name))throw new BusinessException("ROLE_NAME_RESERVED","Este nome de perfil é reservado pela plataforma");}
    private String generateTemporaryPassword(){var value=new StringBuilder(PASSWORD_LENGTH);for(int i=0;i<PASSWORD_LENGTH;i++)value.append(PASSWORD_ALPHABET.charAt(random.nextInt(PASSWORD_ALPHABET.length())));return value.toString();}
    private TeamUserResponse toUser(User user){
        return new TeamUserResponse(user.getId(),user.getName(),user.getEmail(),user.getStatus().name(),
                user.getRoles().stream().sorted(Comparator.comparing(Role::getName,String.CASE_INSENSITIVE_ORDER)).map(r->new RoleSummary(r.getId(),r.getName())).toList(),user.isPasswordChangeRequired());
    }
    private RoleResponse toRole(Role role){return new RoleResponse(role.getId(),role.getName(),role.isTemplate(),role.getPermissions().stream().map(Permission::getName).sorted().toList());}

    public record CreateUserRequest(@NotBlank @Email @Size(max=255) String email,@NotBlank @Size(max=120) String name,@NotEmpty Set<Long> roleIds){}
    public record CreatedUserResponse(Long id,String email,String name,String temporaryPassword){}
    public record UpdateUserRequest(Set<Long> roleIds,@Pattern(regexp="ACTIVE|INACTIVE") String status){}
    public record TemporaryPasswordResponse(String temporaryPassword){}
    public record TeamUserResponse(Long id,String name,String email,String status,List<RoleSummary> roles,boolean passwordChangeRequired){}
    public record RoleSummary(Long id,String name){}
    public record CreateRoleRequest(@NotBlank @Size(max=80) String name,@NotEmpty Set<@NotBlank @Size(max=120) String> permissionNames){}
    public record UpdateRoleRequest(@Size(max=80) String name,Set<@NotBlank @Size(max=120) String> permissionNames){}
    public record RoleResponse(Long id,String name,boolean template,List<String> permissions){}
}
