CREATE TABLE security.user_context_scopes (
    user_id BIGINT NOT NULL,
    context_code NVARCHAR(80) NOT NULL,
    CONSTRAINT pk_user_context_scopes PRIMARY KEY (user_id, context_code),
    CONSTRAINT fk_user_context_scopes_user FOREIGN KEY (user_id) REFERENCES security.users(id)
);

CREATE INDEX ix_user_context_scopes_context_code ON security.user_context_scopes(context_code);
