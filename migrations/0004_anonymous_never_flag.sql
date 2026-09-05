-- Admin knob letting anonymous uploads/pastes use never-expiry.
-- Default off (code falls back to false when the row is missing); the
-- seed keeps fresh installs consistent with the other flags.
INSERT INTO instance_config (key, value) VALUES
    ('allow_anonymous_never_expiry', 'false')
ON CONFLICT (key) DO NOTHING;
