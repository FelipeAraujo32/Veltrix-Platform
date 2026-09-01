package br.com.veltrix.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Executa os statements reais de V9__permission_scope.sql (UPDATE da allow-list e DELETE de higiene
 * dos templates) contra um H2 semeado com o catálogo completo (V3+V5+V7+V8) e o "Admin da Conta"
 * como o V8 o deixa (LIKE 'BILLING_%'). Só o ALTER guardado por sys.columns (T-SQL) é substituído
 * pelo ADD COLUMN equivalente.
 */
class PermissionScopeMigrationTest {
    private static final List<String> CATALOG = List.of(
            // V3 — Ouvidoria
            "OUVIDORIA_MANIFESTATION_READ", "OUVIDORIA_MANIFESTATION_TRIAGE", "OUVIDORIA_MANIFESTATION_ASSIGN",
            "OUVIDORIA_MANIFESTATION_RESPOND", "OUVIDORIA_MANIFESTATION_CLOSE", "OUVIDORIA_MANIFESTATION_VIEW_SENSITIVE",
            "OUVIDORIA_REPORT_READ", "OUVIDORIA_CONFIGURATION_MANAGE", "OUVIDORIA_AI_REVIEW", "OUVIDORIA_TELEPHONY_ACCESS",
            // V5 — comercial/billing/LGPD
            "OUVIDORIA_ACCESS", "BILLING_ACCESS", "BILLING_PRODUCT_READ", "BILLING_PRODUCT_MANAGE",
            "BILLING_PACKAGE_READ", "BILLING_PACKAGE_MANAGE", "BILLING_PLAN_READ", "BILLING_PLAN_MANAGE",
            "BILLING_SUBSCRIPTION_READ", "BILLING_SUBSCRIPTION_MANAGE", "BILLING_INVOICE_READ",
            "BILLING_PAYMENT_READ", "BILLING_REFUND_CREATE", "BILLING_ENTITLEMENT_READ",
            "BILLING_ENTITLEMENT_OVERRIDE", "BILLING_WEBHOOK_REPROCESS", "BILLING_RECONCILIATION_EXECUTE",
            "BILLING_FINANCIAL_REPORT_READ", "LEGAL_DOCUMENT_MANAGE", "LEGAL_ACCEPTANCE_READ",
            "PRIVACY_REQUEST_MANAGE", "DATA_RETENTION_MANAGE", "SENSITIVE_DATA_EXPORT",
            // V7 — Financeiro
            "FINANCE_ACCESS", "FINANCE_REPORT_READ", "FINANCE_CHARGE_MANAGE",
            // V8 — gestão de equipe
            "ACCOUNT_TEAM_MANAGE");

    @Test
    void v9MarcaSomenteTenantGradeELimpaPermissoesDePlataformaDosTemplates() throws Exception {
        try (Connection db = DriverManager.getConnection("jdbc:h2:mem:v9-" + System.nanoTime(), "sa", "");
             Statement st = db.createStatement()) {
            st.execute("CREATE SCHEMA security");
            st.execute("CREATE TABLE security.permissions(id BIGINT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(120) NOT NULL)");
            st.execute("CREATE TABLE security.roles(id BIGINT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(80) NOT NULL, tenant_id VARCHAR(80))");
            st.execute("CREATE TABLE security.role_permissions(role_id BIGINT NOT NULL, permission_id BIGINT NOT NULL)");
            for (String name : CATALOG) st.execute("INSERT INTO security.permissions(name) VALUES ('" + name + "')");
            st.execute("INSERT INTO security.roles(name, tenant_id) VALUES ('Admin da Conta', NULL)");
            // Seed exatamente como o V8: ACCOUNT_TEAM_MANAGE + LIKE 'BILLING_%' (o over-grant) + acessos.
            st.execute("INSERT INTO security.role_permissions(role_id, permission_id) SELECT r.id, p.id FROM security.roles r, security.permissions p "
                    + "WHERE r.name = 'Admin da Conta' AND (p.name = 'ACCOUNT_TEAM_MANAGE' OR p.name LIKE 'BILLING\\_%' ESCAPE '\\' OR p.name IN ('OUVIDORIA_ACCESS', 'FINANCE_ACCESS'))");

            for (String statement : v9Statements()) st.execute(statement);

            Set<String> assignable = names(st, "SELECT name FROM security.permissions WHERE tenant_assignable = 1");
            assertThat(assignable).containsExactlyInAnyOrder(
                    "ACCOUNT_TEAM_MANAGE",
                    "OUVIDORIA_ACCESS", "OUVIDORIA_MANIFESTATION_READ", "OUVIDORIA_MANIFESTATION_TRIAGE",
                    "OUVIDORIA_MANIFESTATION_ASSIGN", "OUVIDORIA_MANIFESTATION_RESPOND", "OUVIDORIA_MANIFESTATION_CLOSE",
                    "OUVIDORIA_MANIFESTATION_VIEW_SENSITIVE", "OUVIDORIA_REPORT_READ", "OUVIDORIA_CONFIGURATION_MANAGE",
                    "OUVIDORIA_AI_REVIEW", "OUVIDORIA_TELEPHONY_ACCESS",
                    "FINANCE_ACCESS", "FINANCE_REPORT_READ",
                    "BILLING_ACCESS", "BILLING_SUBSCRIPTION_MANAGE",
                    "BILLING_PRODUCT_READ", "BILLING_PACKAGE_READ", "BILLING_PLAN_READ", "BILLING_SUBSCRIPTION_READ",
                    "BILLING_INVOICE_READ", "BILLING_PAYMENT_READ", "BILLING_ENTITLEMENT_READ", "BILLING_FINANCIAL_REPORT_READ");
            // Fail-closed: nada de OVERRIDE/REFUND/RECONCILIATION/WEBHOOK, LGPD, LEGAL ou *_MANAGE de plataforma.
            assertThat(assignable).doesNotContain("BILLING_ENTITLEMENT_OVERRIDE", "BILLING_REFUND_CREATE",
                    "BILLING_RECONCILIATION_EXECUTE", "BILLING_WEBHOOK_REPROCESS", "SENSITIVE_DATA_EXPORT",
                    "DATA_RETENTION_MANAGE", "LEGAL_DOCUMENT_MANAGE", "PRIVACY_REQUEST_MANAGE");

            Set<String> adminConta = names(st, "SELECT p.name FROM security.role_permissions rp "
                    + "JOIN security.permissions p ON p.id = rp.permission_id JOIN security.roles r ON r.id = rp.role_id WHERE r.name = 'Admin da Conta'");
            assertThat(adminConta).doesNotContain("BILLING_ENTITLEMENT_OVERRIDE", "BILLING_REFUND_CREATE",
                    "BILLING_RECONCILIATION_EXECUTE", "BILLING_WEBHOOK_REPROCESS",
                    "BILLING_PRODUCT_MANAGE", "BILLING_PACKAGE_MANAGE", "BILLING_PLAN_MANAGE");
            assertThat(adminConta).contains("ACCOUNT_TEAM_MANAGE", "OUVIDORIA_ACCESS", "FINANCE_ACCESS",
                    "BILLING_ACCESS", "BILLING_SUBSCRIPTION_MANAGE", "BILLING_SUBSCRIPTION_READ", "BILLING_INVOICE_READ");
        }
    }

    private List<String> v9Statements() throws Exception {
        String sql = Files.readString(Path.of("src", "main", "resources", "db", "migration", "V9__permission_scope.sql"));
        List<String> statements = new ArrayList<>();
        for (String chunk : sql.split("(?m)^\\s*GO\\s*$")) {
            String statement = chunk.trim();
            if (statement.isBlank()) continue;
            // Guard T-SQL (sys.columns) não roda no H2: aplica o ADD COLUMN equivalente no lugar.
            statements.add(statement.contains("sys.columns")
                    ? "ALTER TABLE security.permissions ADD tenant_assignable INT NOT NULL DEFAULT 0" : statement);
        }
        assertThat(statements).hasSize(3); // ALTER + UPDATE allow-list + DELETE de higiene
        return statements;
    }

    private Set<String> names(Statement st, String query) throws Exception {
        Set<String> result = new HashSet<>();
        try (ResultSet rs = st.executeQuery(query)) { while (rs.next()) result.add(rs.getString(1)); }
        return result;
    }
}
