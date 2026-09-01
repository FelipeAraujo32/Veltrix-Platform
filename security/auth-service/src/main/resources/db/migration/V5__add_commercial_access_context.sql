ALTER TABLE security.users ADD tenant_id NVARCHAR(80) NOT NULL CONSTRAINT df_users_tenant DEFAULT 'DEFAULT';
ALTER TABLE security.users ADD active_base_id NVARCHAR(80) NULL;
ALTER TABLE security.users ADD access_version BIGINT NOT NULL CONSTRAINT df_users_access_version DEFAULT 0;
ALTER TABLE security.users ADD token_version BIGINT NOT NULL CONSTRAINT df_users_token_version DEFAULT 0;
GO

CREATE TABLE security.user_base_access (
 user_id BIGINT NOT NULL, tenant_id NVARCHAR(80) NOT NULL, base_id NVARCHAR(80) NOT NULL, active BIT NOT NULL DEFAULT 1,
 created_at DATETIMEOFFSET(7) NOT NULL DEFAULT SYSDATETIMEOFFSET(),
 CONSTRAINT pk_user_base_access PRIMARY KEY(user_id,tenant_id,base_id),
 CONSTRAINT fk_user_base_access_user FOREIGN KEY(user_id) REFERENCES security.users(id)
);
CREATE INDEX ix_user_base_access_scope ON security.user_base_access(tenant_id,base_id,user_id);
GO

INSERT INTO security.user_base_access(user_id,tenant_id,base_id)
SELECT u.id,u.tenant_id,s.context_code FROM security.users u JOIN security.user_context_scopes s ON s.user_id=u.id WHERE s.context_code<>'*';

DECLARE @permissions TABLE(name NVARCHAR(120));
INSERT INTO @permissions(name) VALUES
('OUVIDORIA_ACCESS'),('BILLING_ACCESS'),('BILLING_PRODUCT_READ'),('BILLING_PRODUCT_MANAGE'),
('BILLING_PACKAGE_READ'),('BILLING_PACKAGE_MANAGE'),('BILLING_PLAN_READ'),('BILLING_PLAN_MANAGE'),
('BILLING_SUBSCRIPTION_READ'),('BILLING_SUBSCRIPTION_MANAGE'),('BILLING_INVOICE_READ'),
('BILLING_PAYMENT_READ'),('BILLING_REFUND_CREATE'),('BILLING_ENTITLEMENT_READ'),
('BILLING_ENTITLEMENT_OVERRIDE'),('BILLING_WEBHOOK_REPROCESS'),('BILLING_RECONCILIATION_EXECUTE'),
('BILLING_FINANCIAL_REPORT_READ'),('LEGAL_DOCUMENT_MANAGE'),('LEGAL_ACCEPTANCE_READ'),
('PRIVACY_REQUEST_MANAGE'),('DATA_RETENTION_MANAGE'),('SENSITIVE_DATA_EXPORT');
INSERT INTO security.permissions(name)
SELECT p.name FROM @permissions p WHERE NOT EXISTS(SELECT 1 FROM security.permissions x WHERE x.name=p.name);

DECLARE @ouvidoriaAccess BIGINT=(SELECT id FROM security.permissions WHERE name='OUVIDORIA_ACCESS');
INSERT INTO security.role_permissions(role_id,permission_id)
SELECT DISTINCT rp.role_id,@ouvidoriaAccess FROM security.role_permissions rp JOIN security.permissions p ON p.id=rp.permission_id
WHERE p.name LIKE 'OUVIDORIA[_]%' AND NOT EXISTS(SELECT 1 FROM security.role_permissions existing WHERE existing.role_id=rp.role_id AND existing.permission_id=@ouvidoriaAccess);
