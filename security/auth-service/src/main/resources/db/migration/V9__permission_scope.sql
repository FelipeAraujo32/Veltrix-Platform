-- Escopo de permissão (PLATFORM vs TENANT), fail-closed: tenant_assignable = 0 por padrão.
-- Um gestor de equipe (ACCOUNT_TEAM_MANAGE) só pode conceder permissões com tenant_assignable = 1;
-- todo o resto é operação de plataforma (OVERRIDE/REFUND/RECONCILIATION/WEBHOOK, LEGAL, PRIVACY,
-- retenção e export de dados sensíveis) e fica fora do alcance de qualquer conta.
-- Idempotente e não destrutivo: guard no ALTER; UPDATE/DELETE são reexecutáveis com o mesmo resultado.

IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('security.permissions') AND name = 'tenant_assignable')
    ALTER TABLE security.permissions ADD tenant_assignable BIT NOT NULL CONSTRAINT df_permissions_tenant_assignable DEFAULT 0;
GO

-- Allow-list explícita (fail-closed: o que não estiver aqui permanece 0 = somente plataforma):
-- gestão de equipe, todo o módulo Ouvidoria, acesso/leituras do Financeiro e billing tenant-grade
-- (acesso, leituras e gestão da própria assinatura). LIKE com ESCAPE para '_' literal.
UPDATE security.permissions SET tenant_assignable = 1
WHERE name = 'ACCOUNT_TEAM_MANAGE'
   OR name LIKE 'OUVIDORIA\_%' ESCAPE '\'
   OR name IN ('FINANCE_ACCESS', 'BILLING_ACCESS', 'BILLING_SUBSCRIPTION_MANAGE')
   OR (name LIKE 'FINANCE\_%' ESCAPE '\' AND name LIKE '%\_READ' ESCAPE '\')
   OR (name LIKE 'BILLING\_%' ESCAPE '\' AND name LIKE '%\_READ' ESCAPE '\');
GO

-- Higiene dos templates globais: template (tenant_id NULL) é atribuível por qualquer tenant, então
-- não pode carregar permissão de plataforma. Corrige o "Admin da Conta" do V8 (o LIKE 'BILLING_%'
-- puxava OVERRIDE/REFUND/RECONCILIATION/WEBHOOK_REPROCESS) sem editar o V8 já aplicado (checksum Flyway).
DELETE FROM security.role_permissions
WHERE permission_id IN (SELECT id FROM security.permissions WHERE tenant_assignable = 0)
  AND role_id IN (SELECT id FROM security.roles WHERE tenant_id IS NULL);
GO
