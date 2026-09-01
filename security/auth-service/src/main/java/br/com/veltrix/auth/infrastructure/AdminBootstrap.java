package br.com.veltrix.auth.infrastructure;

import br.com.veltrix.auth.domain.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
public class AdminBootstrap implements CommandLineRunner {
    private final UserRepository users; private final RoleRepository roles; private final PasswordEncoder encoder;
    private final PermissionRepository permissions;
    private final boolean enabled; private final String email,password,name;
    public AdminBootstrap(UserRepository users,RoleRepository roles,PermissionRepository permissions,PasswordEncoder encoder,
            @Value("${auth.bootstrap.enabled:false}") boolean enabled,
            @Value("${auth.bootstrap.email:}") String email,
            @Value("${auth.bootstrap.password:}") String password,
            @Value("${auth.bootstrap.name:Administrador}") String name){this.users=users;this.roles=roles;this.permissions=permissions;this.encoder=encoder;this.enabled=enabled;this.email=email;this.password=password;this.name=name;}
    @Override @Transactional public void run(String... args){
        if(!enabled) return;
        if(email.isBlank() || password.length()<8) throw new IllegalStateException("AUTH_BOOTSTRAP_EMAIL e AUTH_BOOTSTRAP_PASSWORD (mínimo 8 caracteres) são obrigatórios");
        // Escopado ao tenant da plataforma: ADMIN nunca pode nascer como template (tenant_id NULL),
        // senão qualquer gestor de equipe conseguiria atribuí-lo a um usuário do próprio tenant (escalada).
        Role admin=roles.findByNameAndTenantId("ADMIN","DEFAULT").orElseGet(()->roles.save(new Role("ADMIN","DEFAULT")));
        // Admin da plataforma recebe TODAS as permissões existentes (hoje, as ACCOUNT_* da
        // gestão de equipe). Módulos futuros semeiam as suas e o bootstrap segue válido.
        permissions.findAll().forEach(admin::addPermission);
        User user=users.findByEmailIgnoreCase(email).orElseGet(()->new User(email,encoder.encode(password),name,UserStatus.ACTIVE));
        user.addRole(admin); user.addContextScope("*"); users.save(user);
    }
}
