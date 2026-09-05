-- Never-expiring content: NULL expires_at means "keep until deleted".
-- Only authenticated uploads/pastes may set it (enforced in code); the
-- sweeper and all live-content guards treat NULL as unexpired.
ALTER TABLE files ALTER COLUMN expires_at DROP NOT NULL;
ALTER TABLE pastes ALTER COLUMN expires_at DROP NOT NULL;
