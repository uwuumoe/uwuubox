-- Expansion: dedupe objects, burn-after-read, access passwords, scan status,
-- markdown pastes, roles + OIDC group mapping, quotas, email reset, passkeys,
-- invites, token scopes/expiry, audit log, collections, comments.
--
-- Conventions: new NULL-able or DEFAULTed columns only (existing rows stay
-- valid); no FK from files/pastes to objects (delete order is object-after-
-- last-row, enforced in code with row locks, so RESTRICT would only get in
-- the way).

-- Content-addressed objects for upload dedupe. files.storage_key keeps
-- working: deduped rows simply share the canonical key of the first upload.
CREATE TABLE objects (
    sha256 BYTEA PRIMARY KEY,
    storage_key TEXT NOT NULL UNIQUE,
    size_bytes BIGINT NOT NULL,
    mime_stored TEXT NOT NULL,
    refcount INTEGER NOT NULL DEFAULT 1 CHECK (refcount >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO objects (sha256, storage_key, size_bytes, mime_stored, refcount, created_at)
SELECT sha256, MIN(storage_key), MAX(size_bytes), MAX(mime_stored), COUNT(*), MIN(created_at)
FROM files
GROUP BY sha256;
-- Point duplicate rows at the surviving canonical key.
UPDATE files f
SET storage_key = o.storage_key
FROM objects o
WHERE f.sha256 = o.sha256 AND f.storage_key <> o.storage_key;

ALTER TABLE files
    ADD COLUMN burn_after_read BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN access_password_hash TEXT,
    ADD COLUMN scan_status TEXT NOT NULL DEFAULT 'skipped';

ALTER TABLE pastes
    ADD COLUMN burn_after_read BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN format TEXT NOT NULL DEFAULT 'code' CHECK (format IN ('code', 'markdown')),
    ADD COLUMN access_password_hash TEXT;

-- Roles: NULL limit/quota = fall back to instance default (unlimited quota).
CREATE TABLE roles (
    id UUID PRIMARY KEY,
    name CITEXT NOT NULL UNIQUE,
    max_file_bytes BIGINT,
    max_paste_bytes BIGINT,
    max_avatar_bytes BIGINT,
    min_expiry_secs BIGINT,
    max_expiry_secs BIGINT,
    default_expiry_secs BIGINT,
    quota_bytes BIGINT,
    can_publish_public BOOLEAN NOT NULL DEFAULT TRUE,
    can_burn BOOLEAN NOT NULL DEFAULT TRUE,
    can_comment BOOLEAN NOT NULL DEFAULT TRUE,
    can_create_collections BOOLEAN NOT NULL DEFAULT TRUE,
    can_moderate BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE users
    ADD COLUMN role_id UUID REFERENCES roles (id) ON DELETE SET NULL,
    ADD COLUMN quota_override_bytes BIGINT,
    ADD COLUMN strip_exif_default BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN email CITEXT UNIQUE;

-- OIDC group -> role mapping. Only fills an empty role (admin assignment is
-- sticky); lowest priority number wins on first match.
CREATE TABLE role_oidc_groups (
    role_id UUID NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    issuer TEXT NOT NULL,
    group_name TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (role_id, issuer, group_name)
);

CREATE TABLE password_resets (
    token_hash TEXT PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX password_resets_user_idx ON password_resets (user_id);

CREATE TABLE passkeys (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    cred_id BYTEA NOT NULL UNIQUE,
    public_key BYTEA NOT NULL,
    counter BIGINT NOT NULL DEFAULT 0,
    name TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX passkeys_user_idx ON passkeys (user_id);

-- Invite-code registration. max_uses NULL = unlimited.
CREATE TABLE invite_codes (
    code TEXT PRIMARY KEY,
    created_by UUID REFERENCES users (id) ON DELETE SET NULL,
    max_uses INTEGER,
    uses INTEGER NOT NULL DEFAULT 0 CHECK (uses >= 0),
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE invite_redemptions (
    code TEXT NOT NULL REFERENCES invite_codes (code) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (code, user_id)
);

ALTER TABLE api_tokens
    ADD COLUMN scopes TEXT[] NOT NULL DEFAULT '{upload,paste,delete,read}',
    ADD COLUMN expires_at TIMESTAMPTZ;

CREATE TABLE admin_audit_log (
    id BIGSERIAL PRIMARY KEY,
    actor_id UUID REFERENCES users (id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    detail JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX admin_audit_log_created_idx ON admin_audit_log (created_at DESC);

CREATE TABLE collections (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    visibility TEXT NOT NULL DEFAULT 'unlisted' CHECK (visibility IN ('unlisted', 'public')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX collections_owner_idx ON collections (owner_id, created_at DESC);
CREATE TABLE collection_items (
    collection_id UUID NOT NULL REFERENCES collections (id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('file', 'paste')),
    core TEXT NOT NULL,
    position INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (collection_id, kind, core)
);

CREATE TABLE comments (
    id BIGSERIAL PRIMARY KEY,
    target_kind TEXT NOT NULL CHECK (target_kind IN ('file', 'paste', 'collection')),
    target_core TEXT NOT NULL,
    author_id UUID REFERENCES users (id) ON DELETE SET NULL,
    body TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX comments_target_idx ON comments (target_kind, target_core, created_at);

-- New instance knobs. allow_registration=false carries over to closed mode.
INSERT INTO instance_config (key, value) VALUES
    ('registration_mode', 'open'),
    ('scan_uploads', 'false'),
    ('block_encrypted_archives', 'false')
ON CONFLICT (key) DO NOTHING;
UPDATE instance_config SET value = 'closed'
WHERE key = 'registration_mode'
  AND (SELECT value FROM instance_config WHERE key = 'allow_registration') = 'false';
