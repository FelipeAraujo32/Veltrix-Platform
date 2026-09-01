CREATE TABLE security.auth_audit (
 id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY, actor_id NVARCHAR(120) NULL, action NVARCHAR(120) NOT NULL,
 target_id NVARCHAR(120) NULL, outcome NVARCHAR(40) NOT NULL, correlation_id NVARCHAR(100) NULL,
 ip_address NVARCHAR(64) NULL, user_agent NVARCHAR(500) NULL, created_at DATETIMEOFFSET(7) NOT NULL
);
CREATE INDEX ix_auth_audit_created ON security.auth_audit(created_at);
CREATE INDEX ix_auth_audit_correlation ON security.auth_audit(correlation_id);
