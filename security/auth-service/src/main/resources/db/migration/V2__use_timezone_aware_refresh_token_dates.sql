ALTER TABLE security.refresh_tokens ALTER COLUMN expires_at datetimeoffset(7) NOT NULL;
ALTER TABLE security.refresh_tokens ALTER COLUMN revoked_at datetimeoffset(7) NULL;
