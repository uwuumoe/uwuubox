-- Master switch for never-expiry (logged-in users). Default on, preserving
-- the behavior from 0003; the anonymous knob from 0004 extends it.
INSERT INTO instance_config (key, value) VALUES
    ('allow_never_expiry', 'true')
ON CONFLICT (key) DO NOTHING;
