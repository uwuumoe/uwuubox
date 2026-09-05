-- Link-embed thumbnails for videos: files.thumb_key references a JPEG
-- object (same content-addressed `objects` table as file bytes) holding a
-- frame with a play-button overlay. Crawlers get it as og:image when the
-- video itself is too large to embed.
ALTER TABLE files ADD COLUMN thumb_key TEXT;
