# uwuubox

Self-hostable file sharing in the catbox/0x0st/uguu spirit: upload a file or
paste some text, get a shareable link. Rust + Axum + Askama, PostgreSQL via
SQLx, local-FS or S3-compatible storage, full accounts with local passwords
and one generic OIDC provider.

## Quick start (compose)

```sh
export UWUU_SESSION_SECRET="$(openssl rand -hex 32)"
docker compose up --build
```

Open `http://127.0.0.1:3000`. The **first registered user becomes admin**
(there is no other bootstrap); the home page shows a banner until someone
registers.

Local dev without compose:

```sh
cp .env.example .env   # edit UWUU_SESSION_SECRET + DATABASE_URL
cargo run              # runs embedded SQLx migrations on boot, then serves
```

Health: `GET /health` → `{"ok": true}`.

## Configuration

Infra and secrets come from the environment (`UWUU_` prefix); branding,
limits, and toggles live in the `instance_config` table and are edited at
`/admin` (every key rendered as a typed field).

| var | required | default | notes |
| --- | --- | --- | --- |
| `UWUU_DATABASE_URL` | yes | — | `postgres://user:pass@host/db` |
| `UWUU_SESSION_SECRET` | yes | — | 64 hex chars (`openssl rand -hex 32`); peppers token hashes |
| `UWUU_PORT` | no | `3000` | bind port |
| `UWUU_BASE_URL` | no | `http://127.0.0.1:{port}` | canonical origin for links + OpenGraph; set to your public origin in prod |
| `UWUU_STORAGE_BACKEND` | no | `local` | `local` \| `s3` |
| `UWUU_LOCAL_DIR` | no | `./data` | local object root (`files/`, `avatars/`) |
| `UWUU_S3_ENDPOINT` | s3 only | — | e.g. `http://127.0.0.1:9000` (MinIO), Garage, or R2 endpoint |
| `UWUU_S3_BUCKET` | s3 only | — | must already exist |
| `UWUU_S3_REGION` | no | `auto` | for R2 set the account region + `UWUU_S3_PATH_STYLE=false` |
| `UWUU_S3_ACCESS_KEY` / `UWUU_S3_SECRET_KEY` | s3 only | — | — |
| `UWUU_S3_PATH_STYLE` | no | `true` | path-style URLs (MinIO/Garage need this) |
| `UWUU_STORAGE_ENCRYPTION_KEY` | no | — | 64 hex chars (`openssl rand -hex 32`); XChaCha20-Poly1305 at-rest encryption for `files/` + `avatars/`; unset = plaintext |
| `UWUU_OIDC_ENABLED` | no | `false` | wire up the single generic provider |
| `UWUU_OIDC_DISCOVERY_URL` | oidc only | — | **issuer** URL, e.g. `https://accounts.google.com` (discovery doc is derived) |
| `UWUU_OIDC_CLIENT_ID` / `UWUU_OIDC_CLIENT_SECRET` | oidc only | — | — |
| `UWUU_OIDC_REDIRECT_URL` | oidc only | — | must exactly match the provider's registered callback, e.g. `https://you.host/oidc/callback` |
| `UWUU_SMTP_HOST` / `UWUU_SMTP_PORT` | no | — / `587` | password-reset mail; unset disables reset mail |
| `UWUU_SMTP_USER` / `UWUU_SMTP_PASS` | no | — | SMTP auth (optional) |
| `UWUU_SMTP_FROM` | smtp only | — | `From:` address for reset mail |
| `UWUU_SMTP_STARTTLS` | no | `true` | set `false` for plaintext relays |
| `UWUU_SCAN_COMMAND` | no | — | external scan hook (`cmd <path> <mime>`); exit 0 clean, 3 infected |
| `UWUU_SCAN_TIMEOUT_SECS` | no | `30` | per-file scan timeout |
| `UWUU_SCAN_FAIL_OPEN` | no | `false` | allow uploads when the scanner errors |
| `UWUU_OTEL_ENDPOINT` | no | — | OTLP/HTTP trace export; unset keeps local logs only |

Instance defaults (seeded by migration, editable in admin UI):
`max_file_bytes` 100 MB · `anonymous_max_bytes` 25 MB · `max_paste_bytes`
1 MB · `max_avatar_bytes` 2 MB · expiries min 10 m / default 24 h / max 30 d ·
`allow_anonymous`, `allow_registration`, `allow_local_login` on,
`allow_oidc` off. Oversize uploads get
`413 {"error":"too_large","max_bytes":N}`.

## Using it

```sh
BASE=http://127.0.0.1:3000

# anonymous file upload (always unlisted; keep the delete token)
curl -F file=@screenshot.png $BASE/api/upload
# {"id_core":"…","preview_url":"$BASE/f/…png","raw_url":"$BASE/…png",
#  "expires_at":"…","delete_token":"uwu-del-…"}

# raw bytes back out; sha256 on the preview page matches sha256sum
curl -o out.png "$RAW_URL"

# paste with highlighting
curl -X POST $BASE/api/pastes -H 'Content-Type: application/json' \
  -d '{"body":"fn main() {}","language":"rs"}'
# → {"preview_url":"$BASE/p/…", "raw_url":"$BASE/p/…/raw", …}

# delete anonymously later
curl -X DELETE $BASE/api/files/<core> -H 'Content-Type: application/json' \
  -d '{"delete_token":"uwu-del-…"}'

# authenticated (token from /account → "API tokens")
curl -F file=@x.png -F visibility=public -F expires_in_secs=3600 \
  -H "Authorization: Bearer uwu_…" $BASE/api/upload
```

HTML forms post to the same endpoints: browsers sending
`Accept: text/html` get a `303` to the preview page instead of JSON, so the
site works with JavaScript disabled (JS only adds the progress bar).

ShareX custom uploader (`DestinationType: ImageUploader, FileUploader`):

```json
{
  "Name": "uwuubox",
  "RequestMethod": "POST",
  "RequestURL": "https://you.host/api/upload",
  "Headers": { "Authorization": "Bearer uwu_paste-token-from-/account" },
  "Body": "MultipartFormData",
  "FileFormName": "file",
  "URL": "$json:raw_url$",
  "ThumbnailURL": "$json:preview_url$"
}
```

## Behavior notes

- **IDs/URLs:** 8-char unambiguous cores (`[a-km-np-z2-9]`); every file has
  a preview URL (`/f/<core><ext>`, with OpenGraph) and a raw URL
  (`/<core><ext>`). Extensions are cosmetic — lookup ignores them.
- **MIME is sniffed**, never trusted from the filename. Inline: raster
  images (no SVG), mp4/webm, audio, UTF-8 text. Everything else
  (`text/html`, executables, SVG, unknown) downloads as
  `application/octet-stream` with `nosniff` + `sandbox` headers.
  `text/html`, `application/x-sh`, and Windows/Unix executables are refused
  at upload (`415` naming the MIME).
- **Expiry:** `expires_in_secs` is clamped to `[min, max]`; a sweeper deletes
  objects then rows every 5 minutes. No permanent keeps in v1 (max 30 d).
- **Visibility:** unlisted by default; `public` uploads (anonymous or authed,
  subject to role) appear on the `/explore` feed and on `/u/<you>` for authed
  users. Admin routes 404 for non-admins (no account-enumeration oracle).
- **Rate limits:** 60 uploads/hr/IP overall, 10/hr/IP anonymous,
  5 auth attempts/min/IP, 20 comment posts/min/IP. Raw file/paste bytes support
  single `Range` requests (206); no resumable uploads.
- **At-rest encryption (optional):** set `UWUU_STORAGE_ENCRYPTION_KEY` and new
  objects are sealed before reaching disk/S3, so the provider only ever sees
  ciphertext. Objects written before enabling still read fine; back the key up
  with the database — losing it bricks reads, and unsetting it does not
  decrypt. Seeks on sealed objects cost a full-object fetch (whole-object
  AEAD), and pastes stay plaintext in Postgres.
- **Cookies** are `__Host-` prefixed, `HttpOnly+Secure+SameSite=Lax`; use a
  `localhost`/`127.0.0.1` URL (secure contexts) or HTTPS locally.

## Non-goals (will not be added)

tus/resumable uploads, raw-PUT uploads, multiple OIDC
providers, custom slugs, permanent keeps, image resizing,
root-compat shims for other services, federation.

## Backup & restore

Dump the database through the Compose database service:

```sh
docker compose exec -T db pg_dump -U uwuubox -d uwuubox -Fc > uwuubox.dump
```

For local storage, copy the entire object root (the Compose volume is normally
`/var/lib/docker/volumes/<project>_uwu-data/_data/` on the Docker host):

```sh
rsync -a /path/to/UWUU_LOCAL_DIR/ backup/objects/
```

For an S3 backend, copy the whole bucket with `aws s3 sync` or `rclone sync`,
including both the `files/` and `avatars/` prefixes.

then start the app (migrations run on boot). Keep the same
`UWUU_SESSION_SECRET`, the same `UWUU_STORAGE_ENCRYPTION_KEY` (if set), and the same S3 credentials:

```sh
docker compose stop app
docker compose exec -T db pg_restore -U uwuubox -d uwuubox --clean --if-exists < uwuubox.dump
rsync -a backup/objects/ /path/to/UWUU_LOCAL_DIR/
docker compose start app
```

Do not back up `target/` or temporary scan files. The expiry sweeper runs every
five minutes, so a database restored from a different point in time may refer
to objects that were already swept; run GC after restore, starting with a dry run.
