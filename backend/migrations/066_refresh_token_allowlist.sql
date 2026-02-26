-- Track active refresh tokens by JTI for server-side revocation.
-- On logout or explicit revocation, the JTI is deleted from this table.
-- refresh_tokens() deletes the old JTI and generate_tokens() inserts the new one,
-- providing atomic rotation without double-spend.
CREATE TABLE refresh_token_allowlist (
    jti         VARCHAR(64) PRIMARY KEY,
    user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_refresh_token_allowlist_user    ON refresh_token_allowlist(user_id);
CREATE INDEX idx_refresh_token_allowlist_expires ON refresh_token_allowlist(expires_at);
