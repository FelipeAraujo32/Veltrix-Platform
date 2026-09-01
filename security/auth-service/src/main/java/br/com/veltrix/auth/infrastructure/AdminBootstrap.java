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
        // Fail-closed (mesmo padrão do ProdSecretsGuard): bootstrap ligado sem a senha presente
        // derruba o boot com mensagem clara — em produção a senha NÃO vem de env var, e sim do
        // Docker secret auth_bootstrap_password (arquivo secrets/auth_bootstrap_password, montado
        // como a property auth.bootstrap.password; fica vazio fora da primeira subida).
        if(password.isBlank()) throw new IllegalStateException(
                "auth.bootstrap.enabled=true, mas auth.bootstrap.password está ausente/vazio. Grave a senha no "
                + "arquivo do Docker secret auth_bootstrap_password (./secrets/auth_bootstrap_password) e recrie o "
                + "serviço, ou desligue AUTH_BOOTSTRAP_ENABLED. Refusing to start.");
        if(email.isBlank() || password.length()<8) throw new IllegalStateException(
                "auth.bootstrap.email e auth.bootstrap.password (mínimo 8 caracteres) são obrigatórios quando auth.bootstrap.enabled=true. Refusing to start.");
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
