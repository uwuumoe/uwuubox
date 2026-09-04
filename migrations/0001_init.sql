CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE users (
    id UUID PRIMARY KEY,
    username CITEXT NOT NULL UNIQUE,
    display_name TEXT,
    bio TEXT,
    avatar_key TEXT,
    password_hash TEXT,
    is_admin BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE oidc_identities (
    issuer TEXT NOT NULL,
    sub TEXT NOT NULL,
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    PRIMARY KEY (issuer, sub)
);

CREATE TABLE files (
    id_core CHAR(8) PRIMARY KEY,
    ext TEXT NOT NULL DEFAULT '',
    owner_id UUID REFERENCES users (id) ON DELETE SET NULL,
    original_name TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    mime_stored TEXT NOT NULL,
    sha256 BYTEA NOT NULL,
    storage_key TEXT NOT NULL,
    visibility TEXT NOT NULL DEFAULT 'unlisted' CHECK (visibility IN ('unlisted', 'public')),
    expires_at TIMESTAMPTZ NOT NULL,
    delete_token_hash TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX files_owner_idx ON files (owner_id, created_at DESC);
CREATE INDEX files_expiry_idx ON files (expires_at);

CREATE TABLE pastes (
    id_core CHAR(8) PRIMARY KEY,
    owner_id UUID REFERENCES users (id) ON DELETE SET NULL,
    title TEXT,
    body TEXT NOT NULL,
    language TEXT,
    visibility TEXT NOT NULL DEFAULT 'unlisted' CHECK (visibility IN ('unlisted', 'public')),
    expires_at TIMESTAMPTZ NOT NULL,
    delete_token_hash TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX pastes_owner_idx ON pastes (owner_id, created_at DESC);
CREATE INDEX pastes_expiry_idx ON pastes (expires_at);

CREATE TABLE api_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ
);
CREATE INDEX api_tokens_user_idx ON api_tokens (user_id);

CREATE TABLE instance_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT INTO instance_config (key, value) VALUES
    ('instance_name', 'uwuubox'),
    ('tagline', ''),
    ('icon_url', ''),
    ('max_file_bytes', '104857600'),
    ('max_paste_bytes', '1048576'),
    ('max_avatar_bytes', '2097152'),
    ('min_expiry_secs', '600'),
    ('max_expiry_secs', '2592000'),
    ('default_expiry_secs', '86400'),
    ('allow_anonymous', 'true'),
    ('allow_registration', 'true'),
    ('allow_local_login', 'true'),
    ('allow_oidc', 'false'),
    ('anonymous_max_bytes', '26214400')
ON CONFLICT (key) DO NOTHING;
