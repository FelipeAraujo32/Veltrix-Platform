-- Gestão de equipe (Wave A): perfis por tenant, senha temporária obrigatória e permissão ACCOUNT_TEAM_MANAGE.
-- Idempotente e não destrutivo: todos os passos têm guard e podem ser reexecutados com segurança.

-- roles.tenant_id: NULL = perfil template global (visível a todos os tenants, somente leitura);
-- preenchido = perfil custom pertencente àquele tenant.
IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('security.roles') AND name = 'tenant_id')
    ALTER TABLE security.roles ADD tenant_id NVARCHAR(80) NULL;
GO

IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('security.users') AND name = 'password_change_required')
    ALTER TABLE security.users ADD password_change_required BIT NOT NULL CONSTRAINT df_users_password_change_required DEFAULT 0;
GO

-- Unicidade de nome deixa de ser global e passa a ser por tenant (templates NULL continuam únicos
-- entre si: no SQL Server o índice único trata NULLs como iguais). Remove a UNIQUE de V1 (nome
-- gerado automaticamente) e cria o índice composto.
DECLARE @uq sysname = (SELECT kc.name FROM sys.key_constraints kc WHERE kc.parent_object_id = OBJECT_ID('security.roles') AND kc.type = 'UQ');
IF @uq IS NOT NULL EXEC('ALTER TABLE security.roles DROP CONSTRAINT [' + @uq + ']');
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE object_id = OBJECT_ID('security.roles') AND name = 'uq_roles_tenant_name')
    CREATE UNIQUE INDEX uq_roles_tenant_name ON security.roles(tenant_id, name);
GO

-- Fail-closed: perfis pré-existentes (criados operacionalmente, ex.: ADMIN do bootstrap) NÃO viram
-- templates globais atribuíveis por qualquer tenant — ficam escopados ao tenant da plataforma.
-- Sem isso, um gestor de equipe de qualquer tenant poderia atribuir ADMIN a um usuário (escalada).
UPDATE security.roles SET tenant_id = 'DEFAULT'
WHERE tenant_id IS NULL AND name NOT IN ('Admin da Conta', 'Gestor Ouvidoria', 'Operador Ouvidoria', 'Financeiro');
GO

IF NOT EXISTS (SELECT 1 FROM security.permissions WHERE name = 'ACCOUNT_TEAM_MANAGE')
    INSERT INTO security.permissions(name) VALUES ('ACCOUNT_TEAM_MANAGE');
GO

-- Template: Admin da Conta (gestão de equipe + BILLING completo + acesso aos produtos existentes).
IF NOT EXISTS (SELECT 1 FROM security.roles WHERE name = 'Admin da Conta' AND tenant_id IS NULL)
    INSERT INTO security.roles(name, tenant_id) VALUES ('Admin da Conta', NULL);
DECLARE @adminConta BIGINT = (SELECT id FROM security.roles WHERE name = 'Admin da Conta' AND tenant_id IS NULL);
INSERT INTO security.role_permissions(role_id, permission_id)
SELECT @adminConta, p.id FROM security.permissions p
WHERE (p.name = 'ACCOUNT_TEAM_MANAGE' OR p.name LIKE 'BILLING[_]%' OR p.name IN ('OUVIDORIA_ACCESS', 'FINANCE_ACCESS'))
  AND NOT EXISTS (SELECT 1 FROM security.role_permissions rp WHERE rp.role_id = @adminConta AND rp.permission_id = p.id);
GO

-- Template: Gestor Ouvidoria (todas as permissões do módulo, incluindo OUVIDORIA_ACCESS).
IF NOT EXISTS (SELECT 1 FROM security.roles WHERE name = 'Gestor Ouvidoria' AND tenant_id IS NULL)
    INSERT INTO security.roles(name, tenant_id) VALUES ('Gestor Ouvidoria', NULL);
DECLARE @gestorOuvidoria BIGINT = (SELECT id FROM security.roles WHERE name = 'Gestor Ouvidoria' AND tenant_id IS NULL);
INSERT INTO security.role_permissions(role_id, permission_id)
SELECT @gestorOuvidoria, p.id FROM security.permissions p
WHERE p.name LIKE 'OUVIDORIA[_]%'
  AND NOT EXISTS (SELECT 1 FROM security.role_permissions rp WHERE rp.role_id = @gestorOuvidoria AND rp.permission_id = p.id);
GO

-- Template: Operador Ouvidoria (operação básica: ler, triar e responder manifestações).
IF NOT EXISTS (SELECT 1 FROM security.roles WHERE name = 'Operador Ouvidoria' AND tenant_id IS NULL)
    INSERT INTO security.roles(name, tenant_id) VALUES ('Operador Ouvidoria', NULL);
DECLARE @operadorOuvidoria BIGINT = (SELECT id FROM security.roles WHERE name = 'Operador Ouvidoria' AND tenant_id IS NULL);
INSERT INTO security.role_permissions(role_id, permission_id)
SELECT @operadorOuvidoria, p.id FROM security.permissions p
WHERE p.name IN ('OUVIDORIA_ACCESS', 'OUVIDORIA_MANIFESTATION_READ', 'OUVIDORIA_MANIFESTATION_TRIAGE', 'OUVIDORIA_MANIFESTATION_RESPOND')
  AND NOT EXISTS (SELECT 1 FROM security.role_permissions rp WHERE rp.role_id = @operadorOuvidoria AND rp.permission_id = p.id);
GO

-- Template: Financeiro (módulo financeiro + leitura de billing).
IF NOT EXISTS (SELECT 1 FROM security.roles WHERE name = 'Financeiro' AND tenant_id IS NULL)
    INSERT INTO security.roles(name, tenant_id) VALUES ('Financeiro', NULL);
DECLARE @financeiro BIGINT = (SELECT id FROM security.roles WHERE name = 'Financeiro' AND tenant_id IS NULL);
INSERT INTO security.role_permissions(role_id, permission_id)
SELECT @financeiro, p.id FROM security.permissions p
WHERE (p.name IN ('FINANCE_ACCESS', 'FINANCE_REPORT_READ', 'BILLING_ACCESS') OR (p.name LIKE 'BILLING[_]%' AND p.name LIKE '%[_]READ'))
  AND NOT EXISTS (SELECT 1 FROM security.role_permissions rp WHERE rp.role_id = @financeiro AND rp.permission_id = p.id);
GO
