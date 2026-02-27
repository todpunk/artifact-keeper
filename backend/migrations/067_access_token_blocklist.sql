-- Track revoked access token JTIs for server-side logout invalidation.
-- On logout the access token's JTI is inserted here so a stolen token cannot
-- be replayed even within its 30-minute validity window.
-- Rows are naturally bounded by token lifetime; a periodic cleanup job may
-- DELETE WHERE expires_at < NOW() to keep the table small.
CREATE TABLE access_token_blocklist (
    jti         VARCHAR(64) PRIMARY KEY,
    user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_access_token_blocklist_expires ON access_token_blocklist(expires_at);
