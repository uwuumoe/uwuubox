-- Permanent ID reservation: an 8-char core may never resolve to two
-- different contents over time. `files`/`pastes` PKs only guard live rows,
-- so deleted/expired/burned cores were recyclable. Every allocated core is
-- now claimed here first (INSERT .. ON CONFLICT DO NOTHING decides the
-- winner); the row is never deleted, so the core can never be reissued.
-- Single global namespace: a file core blocks that paste core and vice versa.
CREATE TABLE used_id_cores (
    core CHAR(8) PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('file', 'paste')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Backfill everything ever issued on this instance. If one core somehow
-- exists as both a file and a paste today, the file wins the kind label;
-- either way the core stays reserved.
INSERT INTO used_id_cores (core, kind)
SELECT id_core, 'file' FROM files
ON CONFLICT (core) DO NOTHING;
INSERT INTO used_id_cores (core, kind)
SELECT id_core, 'paste' FROM pastes
ON CONFLICT (core) DO NOTHING;
