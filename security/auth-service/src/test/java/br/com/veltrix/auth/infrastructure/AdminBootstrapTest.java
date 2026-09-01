package br.com.veltrix.auth.infrastructure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import br.com.veltrix.auth.domain.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/** O ADMIN do bootstrap nasce escopado ao tenant DEFAULT: nunca vira template atribuível por outros tenants. */
@SpringBootTest
@ActiveProfiles("test")
class AdminBootstrapTest {
    @Autowired UserRepository users; @Autowired RoleRepository roles; @Autowired PermissionRepository permissions;
    @Autowired RefreshTokenRepository refreshTokens; @Autowired PasswordEncoder encoder; @Autowired PlatformTransactionManager txManager;

    @BeforeEach
    void clean() { refreshTokens.deleteAll(); users.deleteAll(); roles.deleteAll(); permissions.deleteAll(); }

    @Test
    void bootstrapCriaAdminNoTenantDefaultENuncaComoTemplate() {
        permissions.save(new Permission("BILLING_ENTITLEMENT_OVERRIDE"));
        AdminBootstrap bootstrap = new AdminBootstrap(users, roles, permissions, encoder, true, "root@veltrix.com", "senha-bootstrap-123", "Root");
        TransactionTemplate tx = new TransactionTemplate(txManager);
        tx.executeWithoutResult(s -> bootstrap.run());
        assertThatCode(() -> tx.executeWithoutResult(s -> bootstrap.run())).doesNotThrowAnyException(); // reexecução: lookup qualificado por tenant, sem NonUniqueResultException nem duplicata

        Role admin = roles.findByNameAndTenantId("ADMIN", "DEFAULT").orElseThrow();
        assertThat(admin.getTenantId()).isEqualTo("DEFAULT");
        assertThat(admin.isTemplate()).isFalse();
        // Tenant comum não enxerga (logo não consegue atribuir) o ADMIN via gestão de equipe.
        assertThat(roles.findByTenantIdOrTenantIdIsNull("TENANT-A")).extracting(Role::getName).doesNotContain("ADMIN");
        User root = users.findByEmailIgnoreCase("root@veltrix.com").orElseThrow();
        assertThat(root.getRoles()).extracting(Role::getName).containsExactly("ADMIN");
    }
}
