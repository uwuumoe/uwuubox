//! `ObjectStore` trait + local-FS and S3-compatible backends.
//!
//! Key layout: `files/<core><ext>`, `avatars/<uuid><ext>`. Local writes are
//! atomic (tmp file + rename, `0600`); deletes are idempotent so the expiry
//! sweeper can always finish the row delete.
//!
//! Optional at-rest encryption (`UWUU_STORAGE_ENCRYPTION_KEY`): new objects
//! use the v2 chunked STREAM format (`object_crypt`: 24-byte header, then
//! independently-sealed 8 MiB chunks), so multi-GB objects PUT/GET in bounded
//! memory. Legacy v1 whole-object seals still read back; legacy plaintext
//! (no magic) passes through. Plaintext sizes in the DB stay authoritative.
//!
//! Large uploads go through [`Store::put_file`]: the caller spools the body
//! to disk, and this module streams sealed chunks to S3 via concurrent
//! multipart PUTs (4 in flight) or sequential local writes.

use async_trait::async_trait;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use bytes::Bytes;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

use crate::{config::Env, object_crypt};

/// S3 multipart part uploads in flight during [`Store::put_file`].
const MPU_CONCURRENCY: usize = 4;
/// Channel backlog (sealed chunks) between the file pump and the uploader.
const PIPE_DEPTH: usize = 2;
/// Plaintext spans at or below this use one ranged fetch; larger spans
/// stream so a full-file `Range` cannot OOM the pod.
const SPAN_SINGLE_MAX: u64 = 32 * 1024 * 1024;

/// Decrypted download bytes with bounded memory. A mid-stream `Err` ends the
/// body; producers log the cause.
pub type ObjectDataStream = ReceiverStream<Result<Bytes, StorageError>>;
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("object not found: {0}")]
    NotFound(String),
    #[error("storage backend error: {0}")]
    Backend(String),
}

#[async_trait]
pub trait ObjectStore: Clone + Send + Sync + 'static {
    async fn put(&self, key: &str, bytes: Bytes, content_type: &str) -> Result<(), StorageError>;
    async fn get(&self, key: &str) -> Result<Bytes, StorageError>;
    async fn get_range(&self, key: &str, offset: u64, len: u64) -> Result<Bytes, StorageError>;
    async fn delete(&self, key: &str) -> Result<(), StorageError>;
}

#[derive(Debug, Clone)]
pub struct LocalStore {
    pub root: PathBuf,
    pub encryption_key: Option<[u8; 32]>,
}

#[derive(Debug, Clone)]
pub struct S3Store {
    pub client: aws_sdk_s3::Client,
    pub bucket: String,
    pub encryption_key: Option<[u8; 32]>,
}

/// Uniform handle; dispatches to the configured backend.
#[derive(Debug, Clone)]
pub enum Store {
    Local(LocalStore),
    S3(S3Store),
}

pub fn file_key(core: &str, ext: &str) -> String {
    format!("files/{core}{ext}")
}

pub fn avatar_key(id: &Uuid, ext: &str) -> String {
    format!("avatars/{id}{ext}")
}

fn assert_safe_key(key: &str) {
    assert!(
        !key.contains("..") && !key.starts_with('/') && !key.is_empty(),
        "unsafe object key: {key:?}"
    );
}

#[async_trait]
impl ObjectStore for LocalStore {
    async fn put(&self, key: &str, bytes: Bytes, _content_type: &str) -> Result<(), StorageError> {
        assert_safe_key(key);
        let path = self.root.join(key);
        let parent = path
            .parent()
            .ok_or_else(|| StorageError::Backend("bad key".into()))?;
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        // Tmp sibling + rename = atomic publish; 0600 = owner-only.
        let tmp = parent.join(format!(".tmp-{}", Uuid::new_v4().as_simple()));
        tokio::fs::write(&tmp, &bytes)
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perm = std::fs::Permissions::from_mode(0o600);
            tokio::fs::set_permissions(&tmp, perm)
                .await
                .map_err(|e| StorageError::Backend(e.to_string()))?;
        }
        tokio::fs::rename(&tmp, &path)
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Bytes, StorageError> {
        assert_safe_key(key);
        match tokio::fs::read(self.root.join(key)).await {
            Ok(v) => Ok(Bytes::from(v)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(StorageError::NotFound(key.into()))
            }
            Err(e) => Err(StorageError::Backend(e.to_string())),
        }
    }
    async fn get_range(&self, key: &str, offset: u64, len: u64) -> Result<Bytes, StorageError> {
        assert_safe_key(key);
        if len == 0 {
            return Ok(Bytes::new());
        }
        let size = usize::try_from(len)
            .map_err(|_| StorageError::Backend("requested range is too large".into()))?;
        let path = self.root.join(key);
        let mut file = match tokio::fs::File::open(path).await {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(StorageError::NotFound(key.into()))
            }
            Err(e) => return Err(StorageError::Backend(e.to_string())),
        };
        file.seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let mut bytes = vec![0; size];
        file.read_exact(&mut bytes)
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(Bytes::from(bytes))
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        assert_safe_key(key);
        match tokio::fs::remove_file(self.root.join(key)).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StorageError::Backend(e.to_string())),
        }
    }
}

fn is_s3_not_found<E: std::fmt::Debug>(err: &aws_sdk_s3::error::SdkError<E>) -> bool {
    use aws_sdk_s3::error::SdkError;
    match err {
        SdkError::ServiceError(ctx) => {
            let s = format!("{:?}", ctx.err());
            s.contains("NoSuchKey") || s.contains("NotFound") || s.contains("NoSuchBucket")
        }
        _ => false,
    }
}

fn map_s3_get_error<E: std::fmt::Debug>(
    err: &aws_sdk_s3::error::SdkError<E>,
    key: &str,
) -> StorageError {
    if is_s3_not_found(err) {
        StorageError::NotFound(key.into())
    } else {
        StorageError::Backend(err.to_string())
    }
}
#[async_trait]
impl ObjectStore for S3Store {
    async fn put(&self, key: &str, bytes: Bytes, content_type: &str) -> Result<(), StorageError> {
        assert_safe_key(key);
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(bytes))
            .content_type(content_type)
            .send()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Bytes, StorageError> {
        assert_safe_key(key);
        let out = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| {
                if is_s3_not_found(&e) {
                    StorageError::NotFound(key.into())
                } else {
                    StorageError::Backend(e.to_string())
                }
            })?;
        out.body
            .collect()
            .await
            .map(|b| b.into_bytes())
            .map_err(|e| StorageError::Backend(e.to_string()))
    }
    async fn get_range(&self, key: &str, offset: u64, len: u64) -> Result<Bytes, StorageError> {
        assert_safe_key(key);
        if len == 0 {
            return Ok(Bytes::new());
        }
        let end = offset
            .checked_add(len - 1)
            .ok_or_else(|| StorageError::Backend("requested range overflow".into()))?;
        let out = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .range(format!("bytes={offset}-{end}"))
            .send()
            .await
            .map_err(|e| {
                if is_s3_not_found(&e) {
                    StorageError::NotFound(key.into())
                } else {
                    StorageError::Backend(e.to_string())
                }
            })?;
        let bytes = out
            .body
            .collect()
            .await
            .map(|b| b.into_bytes())
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        if bytes.len() as u64 != len {
            return Err(StorageError::Backend(format!(
                "short ranged read: expected {len} bytes, got {}",
                bytes.len()
            )));
        }
        Ok(bytes)
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        assert_safe_key(key);
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(())
    }
}
impl S3Store {
    async fn abort_multipart(&self, key: &str, upload_id: &str) {
        if let Err(error) = self
            .client
            .abort_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .send()
            .await
        {
            tracing::warn!(error = %error, key = %key, "multipart abort failed");
        }
    }

    /// Consume pre-sealed parts (in arrival order) with [`MPU_CONCURRENCY`]
    /// part PUTs in flight, then complete. Aborts the upload on any failure
    /// so no orphaned multipart state lingers in the bucket.
    async fn multipart_upload(
        &self,
        key: &str,
        content_type: &str,
        mut parts: mpsc::Receiver<Bytes>,
    ) -> Result<(), StorageError> {
        assert_safe_key(key);
        let upload_id = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .content_type(content_type)
            .send()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?
            .upload_id
            .ok_or_else(|| StorageError::Backend("multipart create had no upload id".into()))?;

        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(MPU_CONCURRENCY));
        let mut in_flight = JoinSet::new();
        let mut part_no: i32 = 0;
        let mut etags: Vec<(i32, String)> = Vec::new();
        let mut failed: Option<StorageError> = None;
        loop {
            tokio::select! {
                biased;
                Some(done) = in_flight.join_next(), if !in_flight.is_empty() => {
                    match done.map_err(|e| StorageError::Backend(e.to_string()))? {
                        Ok((no, etag)) => etags.push((no, etag)),
                        Err(error) => { failed = Some(error); break; }
                    }
                }
                chunk = parts.recv(), if failed.is_none() => {
                    let Some(body) = chunk else { break };
                    part_no += 1;
                    let no = part_no;
                    let permit = semaphore
                        .clone()
                        .acquire_owned()
                        .await
                        .map_err(|e| StorageError::Backend(e.to_string()))?;
                    let client = self.client.clone();
                    let bucket = self.bucket.clone();
                    let key = key.to_string();
                    let upload_id = upload_id.clone();
                    in_flight.spawn(async move {
                        let _permit = permit;
                        let out = client
                            .upload_part()
                            .bucket(bucket)
                            .key(key)
                            .upload_id(upload_id)
                            .part_number(no)
                            .body(ByteStream::from(body))
                            .send()
                            .await
                            .map_err(|e| StorageError::Backend(e.to_string()))?;
                        let etag = out.e_tag.unwrap_or_default();
                        Ok::<(i32, String), StorageError>((no, etag))
                    });
                }
                else => break,
            }
        }
        // Drain anything still in flight so part tasks never outlive the call.
        while let Some(done) = in_flight.join_next().await {
            match done.map_err(|e| StorageError::Backend(e.to_string()))? {
                Ok((no, etag)) => etags.push((no, etag)),
                Err(error) => failed = failed.or(Some(error)),
            }
        }
        if let Some(error) = failed {
            self.abort_multipart(key, &upload_id).await;
            return Err(error);
        }
        if etags.is_empty() {
            self.abort_multipart(key, &upload_id).await;
            return Err(StorageError::Backend("no parts uploaded".into()));
        }
        etags.sort_by_key(|(no, _)| *no);
        let completed = etags
            .into_iter()
            .map(|(no, etag)| {
                CompletedPart::builder()
                    .part_number(no)
                    .e_tag(etag)
                    .build()
            })
            .collect::<Vec<_>>();
        let upload = CompletedMultipartUpload::builder()
            .set_parts(Some(completed))
            .build();
        self.client
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(&upload_id)
            .multipart_upload(upload)
            .send()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(())
    }
}

impl LocalStore {
    /// Consume pre-sealed parts sequentially into an atomic tmp+rename write.
    async fn stream_write(
        &self,
        key: &str,
        mut parts: mpsc::Receiver<Bytes>,
    ) -> Result<(), StorageError> {
        assert_safe_key(key);
        let path = self.root.join(key);
        let parent = path
            .parent()
            .ok_or_else(|| StorageError::Backend("bad key".into()))?;
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let tmp = parent.join(format!(".tmp-{}", Uuid::new_v4().as_simple()));
        let mut file = tokio::fs::File::create(&tmp)
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        while let Some(part) = parts.recv().await {
            file.write_all(&part)
                .await
                .map_err(|e| StorageError::Backend(e.to_string()))?;
        }
        drop(file);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perm = std::fs::Permissions::from_mode(0o600);
            tokio::fs::set_permissions(&tmp, perm)
                .await
                .map_err(|e| StorageError::Backend(e.to_string()))?;
        }
        tokio::fs::rename(&tmp, &path)
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(())
    }
}

impl Store {
    pub async fn from_env(env: &Env) -> Result<Self, StorageError> {
        match env.storage_backend {
            crate::config::StorageBackend::Local => {
                std::fs::create_dir_all(&env.local_dir)
                    .map_err(|e| StorageError::Backend(e.to_string()))?;
                Ok(Self::Local(LocalStore {
                    root: env.local_dir.clone(),
                    encryption_key: env.storage_encryption_key,
                }))
            }
            crate::config::StorageBackend::S3 => {
                let creds = aws_credential_types::Credentials::new(
                    env.s3_access_key.clone().unwrap_or_default(),
                    env.s3_secret_key.clone().unwrap_or_default(),
                    None,
                    None,
                    "uwuubox-env",
                );
                let builder = aws_config::defaults(aws_config::BehaviorVersion::latest())
                    .region(aws_config::Region::new(env.s3_region.clone()))
                    .endpoint_url(env.s3_endpoint.clone().unwrap_or_default())
                    .credentials_provider(creds);
                let sdk = builder.load().await;
                let mut s3b = aws_sdk_s3::config::Builder::from(&sdk);
                if env.s3_path_style {
                    s3b = s3b.force_path_style(true);
                }
                let client = aws_sdk_s3::Client::from_conf(s3b.build());
                Ok(Self::S3(S3Store {
                    client,
                    bucket: env.s3_bucket.clone().unwrap_or_default(),
                    encryption_key: env.storage_encryption_key,
                }))
            }
        }
    }

    fn encryption_key(&self) -> Option<[u8; 32]> {
        match self {
            Self::Local(s) => s.encryption_key,
            Self::S3(s) => s.encryption_key,
        }
    }

    async fn raw_get(&self, key: &str) -> Result<Bytes, StorageError> {
        match self {
            Self::Local(s) => s.get(key).await,
            Self::S3(s) => s.get(key).await,
        }
    }

    async fn raw_get_range(&self, key: &str, offset: u64, len: u64) -> Result<Bytes, StorageError> {
        match self {
            Self::Local(s) => s.get_range(key, offset, len).await,
            Self::S3(s) => s.get_range(key, offset, len).await,
        }
    }

    /// Best-effort ranged fetch: short reads at EOF come back short instead
    /// of erroring. Only for v2 tail-chunk fetches, where the Poly1305 tag
    /// still fails closed on truncation — every other caller needs exactness.
    async fn raw_get_range_relaxed(
        &self,
        key: &str,
        offset: u64,
        len: u64,
    ) -> Result<Bytes, StorageError> {
        let size = usize::try_from(len)
            .map_err(|_| StorageError::Backend("requested range is too large".into()))?;
        match self {
            Self::Local(s) => {
                assert_safe_key(key);
                let path = s.root.join(key);
                let mut file = tokio::fs::File::open(path).await.map_err(|e| {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        StorageError::NotFound(key.into())
                    } else {
                        StorageError::Backend(e.to_string())
                    }
                })?;
                file.seek(std::io::SeekFrom::Start(offset))
                    .await
                    .map_err(|e| StorageError::Backend(e.to_string()))?;
                let mut bytes = vec![0; size];
                let mut filled = 0;
                while filled < size {
                    match file.read(&mut bytes[filled..]).await {
                        Ok(0) => break,
                        Ok(n) => filled += n,
                        Err(e) => return Err(StorageError::Backend(e.to_string())),
                    }
                }
                bytes.truncate(filled);
                Ok(Bytes::from(bytes))
            }
            Self::S3(s) => {
                assert_safe_key(key);
                if len == 0 {
                    return Ok(Bytes::new());
                }
                let end = offset
                    .checked_add(len - 1)
                    .ok_or_else(|| StorageError::Backend("requested range overflow".into()))?;
                let out = s
                    .client
                    .get_object()
                    .bucket(&s.bucket)
                    .key(key)
                    .range(format!("bytes={offset}-{end}"))
                    .send()
                    .await
                    .map_err(|e| map_s3_get_error(&e, key))?;
                out.body
                    .collect()
                    .await
                    .map(|b| b.into_bytes())
                    .map_err(|e| StorageError::Backend(e.to_string()))
            }
        }
    }

    async fn raw_put(
        &self,
        key: &str,
        bytes: Bytes,
        content_type: &str,
    ) -> Result<(), StorageError> {
        match self {
            Self::Local(s) => s.put(key, bytes, content_type).await,
            Self::S3(s) => s.put(key, bytes, content_type).await,
        }
    }

    pub async fn put(
        &self,
        key: &str,
        bytes: Bytes,
        content_type: &str,
    ) -> Result<(), StorageError> {
        let bytes = match self.encryption_key() {
            Some(k) => object_crypt::seal(&k, &bytes),
            None => bytes,
        };
        self.raw_put(key, bytes, content_type).await
    }

    /// Store a spooled upload file in bounded memory. Reads `path` in
    /// 8 MiB pieces, seals each piece when a key is configured (v2 STREAM
    /// framing), and uploads: one PUT for single-piece objects, concurrent
    /// multipart parts for larger ones. `pt_len` is the exact plaintext size.
    pub async fn put_file(
        &self,
        key: &str,
        path: &Path,
        pt_len: u64,
        content_type: &str,
    ) -> Result<(), StorageError> {
        assert_safe_key(key);
        let framing = match self.encryption_key() {
            Some(k) => {
                let base = object_crypt::stream_base();
                let header = Bytes::from(object_crypt::stream_header(
                    object_crypt::STREAM_CHUNK_PT as u32,
                    &base,
                ));
                Some((k, base, header))
            }
            None => None,
        };
        // The pump only needs key+base (both `Copy`); the header stays here
        // for the single-piece and multipart paths below.
        let seal = framing.as_ref().map(|(k, base, _)| (*k, *base));
        let (tx, mut rx) = mpsc::channel::<Bytes>(PIPE_DEPTH + 1);
        let path = path.to_path_buf();
        let pump = tokio::spawn(async move {
            let mut file = tokio::fs::File::open(&path)
                .await
                .map_err(|e| StorageError::Backend(e.to_string()))?;
            let mut index: u64 = 0;
            let mut buf = vec![0u8; object_crypt::STREAM_CHUNK_PT];
            let mut pieces: u64 = 0;
            loop {
                let mut filled = 0;
                while filled < buf.len() {
                    match file.read(&mut buf[filled..]).await {
                        Ok(0) => break,
                        Ok(n) => filled += n,
                        Err(e) => return Err(StorageError::Backend(e.to_string())),
                    }
                }
                if filled == 0 {
                    break;
                }
                let piece = match &seal {
                    Some((k, base)) => {
                        Bytes::from(object_crypt::seal_chunk(k, base, index, &buf[..filled]))
                    }
                    None => Bytes::copy_from_slice(&buf[..filled]),
                };
                index += 1;
                pieces += 1;
                if tx.send(piece).await.is_err() {
                    return Err(StorageError::Backend("upload consumer went away".into()));
                }
                if filled < buf.len() {
                    break;
                }
            }
            Ok::<u64, StorageError>(pieces)
        });
        // Peek at the first two pieces to choose one PUT vs multipart without
        // re-reading the file.
        let first = rx.recv().await;
        let result = match (self, first) {
            (_, None) if pt_len == 0 => {
                // Empty files never reach here (uploads reject them), but stay
                // total: store the framing header alone when sealed.
                let bytes = framing.map(|(_, _, header)| header).unwrap_or_default();
                self.raw_put(key, bytes, content_type).await
            }
            (_, None) => Err(StorageError::Backend("upload spool vanished".into())),
            (store, Some(first)) => match rx.recv().await {
                None => {
                    // Single piece: prepend the v2 header when sealed.
                    let mut bytes = Vec::new();
                    if let Some((_, _, header)) = &framing {
                        bytes.extend_from_slice(header);
                    }
                    bytes.extend_from_slice(&first);
                    drop(rx);
                    let _ = pump.await;
                    store.raw_put(key, Bytes::from(bytes), content_type).await
                }
                Some(second) => {
                    let (mtx, mrx) = mpsc::channel::<Bytes>(PIPE_DEPTH);
                    // Re-emit in order. The v2 header is fused onto the first
                    // piece: S3 rejects tiny non-final parts, so the 24-byte
                    // header must never fly alone.
                    let header = framing.map(|(_, _, header)| header);
                    let forward = tokio::spawn(async move {
                        let mut fused = Vec::new();
                        if let Some(header) = header {
                            fused.extend_from_slice(&header);
                        }
                        fused.extend_from_slice(&first);
                        if mtx.send(Bytes::from(fused)).await.is_err() {
                            return;
                        }
                        if mtx.send(second).await.is_err() {
                            return;
                        }
                        while let Some(p) = rx.recv().await {
                            if mtx.send(p).await.is_err() {
                                return;
                            }
                        }
                    });
                    let out = match store {
                        Store::Local(s) => s.stream_write(key, mrx).await,
                        Store::S3(s) => s.multipart_upload(key, content_type, mrx).await,
                    };
                    let _ = forward.await;
                    let pumped = match pump.await {
                        Ok(Ok(n)) => n,
                        Ok(Err(e)) => return Err(e),
                        Err(e) => return Err(StorageError::Backend(format!("pump: {e}"))),
                    };
                    if pumped == 0 {
                        return Err(StorageError::Backend("upload spool vanished".into()));
                    }
                    out
                }
            },
        };
        result
    }

    pub async fn get(&self, key: &str) -> Result<Bytes, StorageError> {
        let raw = self.raw_get(key).await?;
        decrypt_if_needed(self.encryption_key(), raw)
    }

    pub async fn delete(&self, key: &str) -> Result<(), StorageError> {
        match self {
            Self::Local(s) => s.delete(key).await,
            Self::S3(s) => s.delete(key).await,
        }
    }

    /// Plaintext byte stream for `key` (no framing, no buffering).
    fn raw_stream(&self, key: &str) -> ReceiverStream<Result<Bytes, StorageError>> {
        let (tx, rx) = mpsc::channel::<Result<Bytes, StorageError>>(PIPE_DEPTH + 1);
        let store = self.clone();
        let key = key.to_string();
        tokio::spawn(async move {
            let result = match &store {
                Store::S3(s) => {
                    assert_safe_key(&key);
                    match s
                        .client
                        .get_object()
                        .bucket(&s.bucket)
                        .key(&key)
                        .send()
                        .await
                    {
                        Ok(out) => {
                            let mut body = out.body;
                            loop {
                                match body.next().await {
                                    Some(Ok(chunk)) => {
                                        if tx.send(Ok(chunk)).await.is_err() {
                                            break;
                                        }
                                    }
                                    Some(Err(e)) => {
                                        let _ = tx
                                            .send(Err(StorageError::Backend(e.to_string())))
                                            .await;
                                        break;
                                    }
                                    None => break,
                                }
                            }
                            Ok(())
                        }
                        Err(e) => Err(map_s3_get_error(&e, &key)),
                    }
                }
                Store::Local(s) => {
                    assert_safe_key(&key);
                    match tokio::fs::File::open(s.root.join(&key)).await {
                        Ok(mut file) => {
                            let mut buf = vec![0u8; object_crypt::STREAM_CHUNK_PT];
                            loop {
                                match file.read(&mut buf).await {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        if tx
                                            .send(Ok(Bytes::copy_from_slice(&buf[..n])))
                                            .await
                                            .is_err()
                                        {
                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        let _ = tx
                                            .send(Err(StorageError::Backend(e.to_string())))
                                            .await;
                                        break;
                                    }
                                }
                            }
                            Ok(())
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                            Err(StorageError::NotFound(key.clone()))
                        }
                        Err(e) => Err(StorageError::Backend(e.to_string())),
                    }
                }
            };
            if let Err(error) = result {
                let _ = tx.send(Err(error)).await;
            }
        });
        ReceiverStream::new(rx)
    }

    /// Full-object plaintext stream in bounded memory. v2 stream-sealed
    /// objects decrypt chunk by chunk; legacy v1 seals and legacy plaintext
    /// use the old buffered path. `pt_len` is the DB-authoritative plaintext
    /// size and bounds the v2 chunk walk, so truncation fails closed.
    pub async fn get_stream(
        &self,
        key: &str,
        pt_len: u64,
    ) -> Result<ReceiverStream<Result<Bytes, StorageError>>, StorageError> {
        let probe = match self.raw_get_range(key, 0, 4).await {
            Ok(probe) => probe,
            Err(StorageError::NotFound(missing)) => return Err(StorageError::NotFound(missing)),
            // Object shorter than the probe: legacy tiny plaintext.
            Err(_) => return Ok(self.raw_stream(key)),
        };
        let Some(k) = self.encryption_key() else {
            // No key: serve legacy plaintext, fail closed on sealed objects
            // instead of leaking ciphertext as a download.
            if object_crypt::is_encrypted(&probe) || object_crypt::is_stream_sealed(&probe) {
                return Err(StorageError::Backend(
                    "object is encrypted but UWUU_STORAGE_ENCRYPTION_KEY is unset".into(),
                ));
            }
            return Ok(self.raw_stream(key));
        };
        if !object_crypt::is_stream_sealed(&probe) {
            // v1 seal or legacy plaintext: buffered legacy path.
            let raw = self.raw_get(key).await?;
            let pt = decrypt_if_needed(Some(k), raw)?;
            let (tx, rx) = mpsc::channel(1);
            let _ = tx.send(Ok(pt)).await;
            return Ok(ReceiverStream::new(rx));
        }
        let header = self.raw_get_range(key, 0, object_crypt::STREAM_HEADER_LEN as u64).await?;
        let (chunk_pt, base) =
            object_crypt::parse_stream_header(&header).map_err(StorageError::Backend)?;
        let count = object_crypt::stream_chunk_count(pt_len, chunk_pt);
        let (tx, rx) = mpsc::channel::<Result<Bytes, StorageError>>(PIPE_DEPTH + 1);
        let store = self.clone();
        let key = key.to_string();
        tokio::spawn(async move {
            let mut off = object_crypt::STREAM_HEADER_LEN as u64;
            let mut remaining = pt_len;
            for index in 0..count {
                let pt_here = remaining.min(chunk_pt as u64);
                let sealed_len = pt_here + 16;
                let sealed = match store.raw_get_range(key.as_str(), off, sealed_len).await {
                    Ok(b) => b,
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        return;
                    }
                };
                if sealed.len() as u64 != sealed_len {
                    let _ = tx
                        .send(Err(StorageError::Backend("truncated stream object".into())))
                        .await;
                    return;
                }
                match object_crypt::open_chunk(&k, &base, index, &sealed) {
                    Ok(pt) => {
                        if tx.send(Ok(Bytes::from(pt))).await.is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(StorageError::Backend(e))).await;
                        return;
                    }
                }
                off += sealed_len;
                remaining -= pt_here;
            }
        });
        Ok(ReceiverStream::new(rx))
    }

    /// Plaintext span `[pt_offset, pt_offset + len)` as a stream. v2 objects
    /// fetch only the covering sealed chunks; plaintext spans at or below
    /// [`SPAN_SINGLE_MAX`] use one ranged fetch, larger ones stream with
    /// skip/take so a full-file `Range` cannot OOM the pod. Legacy v1 seals
    /// use the old buffered slice.
    pub async fn get_range_stream(
        &self,
        key: &str,
        pt_offset: u64,
        len: u64,
    ) -> Result<ReceiverStream<Result<Bytes, StorageError>>, StorageError> {
        if len == 0 {
            let (_, rx) = mpsc::channel(1);
            return Ok(ReceiverStream::new(rx));
        }
        let key_string = key.to_string();
        let probe = match self.raw_get_range(key, 0, 4).await {
            Ok(probe) => probe,
            Err(StorageError::NotFound(missing)) => return Err(StorageError::NotFound(missing)),
            Err(_) => return self.raw_span_stream(&key_string, pt_offset, len).await,
        };
        let Some(k) = self.encryption_key() else {
            if object_crypt::is_encrypted(&probe) || object_crypt::is_stream_sealed(&probe) {
                return Err(StorageError::Backend(
                    "object is encrypted but UWUU_STORAGE_ENCRYPTION_KEY is unset".into(),
                ));
            }
            return self.raw_span_stream(&key_string, pt_offset, len).await;
        };
        if object_crypt::is_stream_sealed(&probe) {
            return self.v2_span_stream(&key_string, k, pt_offset, len).await;
        }
        if object_crypt::is_encrypted(&probe) {
            let raw = self.raw_get(key).await?;
            let pt = decrypt_if_needed(Some(k), raw)?;
            let pt = slice_plaintext(&pt, pt_offset, len)?;
            let (tx, rx) = mpsc::channel(1);
            let _ = tx.send(Ok(pt)).await;
            return Ok(ReceiverStream::new(rx));
        }
        self.raw_span_stream(&key_string, pt_offset, len).await
    }

    async fn raw_span_stream(
        &self,
        key: &str,
        offset: u64,
        len: u64,
    ) -> Result<ReceiverStream<Result<Bytes, StorageError>>, StorageError> {
        if len <= SPAN_SINGLE_MAX {
            let bytes = self.raw_get_range(key, offset, len).await?;
            let (tx, rx) = mpsc::channel(1);
            let _ = tx.send(Ok(bytes)).await;
            return Ok(ReceiverStream::new(rx));
        }
        // Large span: pump the raw stream with skip/take.
        let mut inner = self.raw_stream(key);
        let (tx, rx) = mpsc::channel::<Result<Bytes, StorageError>>(PIPE_DEPTH + 1);
        tokio::spawn(async move {
            use tokio_stream::StreamExt;
            let mut skip = offset;
            let mut take = len;
            while take > 0 {
                match inner.next().await {
                    Some(Ok(chunk)) => {
                        let chunk_len = chunk.len() as u64;
                        if skip >= chunk_len {
                            skip -= chunk_len;
                            continue;
                        }
                        let start = skip as usize;
                        skip = 0;
                        let end = (start as u64 + take).min(chunk_len) as usize;
                        take -= (end - start) as u64;
                        if tx.send(Ok(chunk.slice(start..end))).await.is_err() {
                            return;
                        }
                    }
                    Some(Err(e)) => {
                        let _ = tx.send(Err(e)).await;
                        return;
                    }
                    None => {
                        let _ = tx
                            .send(Err(StorageError::Backend("truncated span".into())))
                            .await;
                        return;
                    }
                }
            }
        });
        Ok(ReceiverStream::new(rx))
    }

    async fn v2_span_stream(
        &self,
        key: &str,
        k: [u8; 32],
        pt_offset: u64,
        len: u64,
    ) -> Result<ReceiverStream<Result<Bytes, StorageError>>, StorageError> {
        let header = self.raw_get_range(key, 0, object_crypt::STREAM_HEADER_LEN as u64).await?;
        let (chunk_pt, base) =
            object_crypt::parse_stream_header(&header).map_err(StorageError::Backend)?;
        let chunk_pt = chunk_pt as u64;
        let first = pt_offset / chunk_pt;
        let last = pt_offset.checked_add(len - 1).map(|end| end / chunk_pt);
        let Some(last) = last else {
            return Err(StorageError::Backend("range overflow".into()));
        };
        let (tx, rx) = mpsc::channel::<Result<Bytes, StorageError>>(PIPE_DEPTH + 1);
        let store = self.clone();
        let key = key.to_string();
        tokio::spawn(async move {
            let mut remaining = len;
            let mut trim = (pt_offset % chunk_pt) as usize;
            for index in first..=last {
                // Sealed extent of chunk `index`. The object's last chunk is
                // shorter; a short read is fine here because the Poly1305 tag
                // still fails closed on any real truncation or tampering.
                let sealed_want = chunk_pt + 16;
                let off = object_crypt::STREAM_HEADER_LEN as u64 + index * sealed_want;
                let sealed = match store
                    .raw_get_range_relaxed(key.as_str(), off, sealed_want)
                    .await
                {
                    Ok(b) => b,
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        return;
                    }
                };
                if sealed.is_empty() {
                    let _ = tx
                        .send(Err(StorageError::Backend("truncated stream object".into())))
                        .await;
                    return;
                }
                match object_crypt::open_chunk(&k, &base, index, &sealed) {
                    Ok(pt) => {
                        let pt = if trim > 0 {
                            if trim >= pt.len() {
                                trim -= pt.len();
                                continue;
                            }
                            let rest = pt[trim..].to_vec();
                            trim = 0;
                            rest
                        } else {
                            pt
                        };
                        let take = (remaining as usize).min(pt.len());
                        remaining -= take as u64;
                        if tx.send(Ok(Bytes::from(pt[..take].to_vec()))).await.is_err() {
                            return;
                        }
                        if remaining == 0 {
                            return;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(StorageError::Backend(e))).await;
                        return;
                    }
                }
            }
        });
        Ok(ReceiverStream::new(rx))
    }
}

/// Open sealed objects; pass legacy plaintext through. Fails closed when the
/// key is missing or the AEAD does not verify — never returns ciphertext as
/// if it were plaintext on the full-object path.
fn decrypt_if_needed(key: Option<[u8; 32]>, raw: Bytes) -> Result<Bytes, StorageError> {
    if !object_crypt::is_encrypted(&raw) {
        return Ok(raw);
    }
    let Some(k) = key else {
        return Err(StorageError::Backend(
            "object is encrypted but UWUU_STORAGE_ENCRYPTION_KEY is unset".into(),
        ));
    };
    object_crypt::open(&k, &raw).map_err(StorageError::Backend)
}

/// Slice already-decrypted plaintext by plaintext offsets (the DB `size_bytes`
/// coordinates callers already use).
fn slice_plaintext(pt: &Bytes, offset: u64, len: u64) -> Result<Bytes, StorageError> {
    let start = usize::try_from(offset)
        .map_err(|_| StorageError::Backend("range offset is too large".into()))?;
    let len = usize::try_from(len)
        .map_err(|_| StorageError::Backend("requested range is too large".into()))?;
    let end = start
        .checked_add(len)
        .ok_or_else(|| StorageError::Backend("requested range overflow".into()))?;
    if end > pt.len() || start > pt.len() {
        return Err(StorageError::Backend(format!(
            "short ranged read: expected {len} bytes at offset {offset}, object holds {}",
            pt.len(),
        )));
    }
    Ok(pt.slice(start..end))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x42; 32];

    fn scratch() -> PathBuf {
        std::env::temp_dir().join(format!("uwuubox-enc-{}", Uuid::new_v4().as_simple()))
    }

    fn local(key: Option<[u8; 32]>) -> (Store, PathBuf) {
        let root = scratch();
        std::fs::create_dir_all(&root).unwrap();
        (
            Store::Local(LocalStore {
                root: root.clone(),
                encryption_key: key,
            }),
            root,
        )
    }

    async fn collect(mut stream: ObjectDataStream) -> Bytes {
        use tokio_stream::StreamExt;
        let mut out = Vec::new();
        while let Some(chunk) = stream.next().await {
            out.extend_from_slice(&chunk.unwrap());
        }
        Bytes::from(out)
    }

    #[tokio::test]
    async fn encrypted_roundtrip_hides_plaintext_on_disk() {
        let (store, root) = local(Some(KEY));
        let pt = Bytes::from_static(b"top secret bytes");
        store
            .put("files/abc12345.png", pt.clone(), "image/png")
            .await
            .unwrap();
        let raw = tokio::fs::read(root.join("files/abc12345.png"))
            .await
            .unwrap();
        assert!(object_crypt::is_encrypted(&raw));
        assert!(!raw.windows(pt.len()).any(|w| w == &pt[..]));
        assert_eq!(store.get("files/abc12345.png").await.unwrap(), pt);
        let ranged = store
            .get_range_stream("files/abc12345.png", 4, 6)
            .await
            .unwrap();
        assert_eq!(collect(ranged).await, pt.slice(4..10));
        tokio::fs::remove_dir_all(&root).await.ok();
    }

    #[tokio::test]
    async fn legacy_plaintext_stays_readable_after_enabling() {
        let (plain, root) = local(None);
        let pt = Bytes::from_static(b"legacy bytes");
        plain
            .put("files/legacy01.txt", pt.clone(), "text/plain")
            .await
            .unwrap();
        let sealed = Store::Local(LocalStore {
            root: root.clone(),
            encryption_key: Some(KEY),
        });
        assert_eq!(sealed.get("files/legacy01.txt").await.unwrap(), pt);
        let ranged = sealed
            .get_range_stream("files/legacy01.txt", 0, 6)
            .await
            .unwrap();
        assert_eq!(collect(ranged).await, pt.slice(0..6));
        // Tiny object (< 4-byte probe): exercises the short-object fallback.
        plain
            .put("files/tiny01.txt", Bytes::from_static(b"hi"), "text/plain")
            .await
            .unwrap();
        let tiny = sealed
            .get_range_stream("files/tiny01.txt", 0, 2)
            .await
            .unwrap();
        assert_eq!(collect(tiny).await, Bytes::from_static(b"hi"));
    }

    /// 20 MiB through `put_file` forces the multi-piece path (8 MiB chunks)
    /// and reads back whole + a cross-chunk span. Deterministic bytes so a
    /// swapped chunk would fail the comparison.
    #[tokio::test]
    async fn put_file_streams_multi_chunk_roundtrip() {
        for key in [Some(KEY), None] {
            let (store, root) = local(key);
            let pt_len = 20 * 1024 * 1024usize;
            let mut pt = vec![0u8; pt_len];
            for (i, byte) in pt.iter_mut().enumerate() {
                *byte = (i.wrapping_mul(2654435761) >> 8) as u8;
            }
            let spool = root.join("spool.bin");
            tokio::fs::write(&spool, &pt).await.unwrap();
            store
                .put_file("files/big01.bin", &spool, pt_len as u64, "application/octet-stream")
                .await
                .unwrap();
            let full = store
                .get_stream("files/big01.bin", pt_len as u64)
                .await
                .unwrap();
            assert_eq!(collect(full).await.as_ref(), pt.as_slice());
            // Span straddling the first chunk boundary.
            let span = store
                .get_range_stream("files/big01.bin", 8 * 1024 * 1024 - 7, 30)
                .await
                .unwrap();
            assert_eq!(
                collect(span).await.as_ref(),
                &pt[8 * 1024 * 1024 - 7..8 * 1024 * 1024 + 23]
            );
            // Tail span hitting the short final chunk (relaxed read path).
            let tail = store
                .get_range_stream("files/big01.bin", pt_len as u64 - 100, 100)
                .await
                .unwrap();
            assert_eq!(collect(tail).await.as_ref(), &pt[pt_len - 100..]);
            tokio::fs::remove_dir_all(&root).await.ok();
        }
    }

    #[tokio::test]
    async fn missing_key_fails_closed() {
        let (sealed, root) = local(Some(KEY));
        sealed
            .put(
                "files/locked01.bin",
                Bytes::from_static(b"nope"),
                "application/octet-stream",
            )
            .await
            .unwrap();
        let naked = Store::Local(LocalStore {
            root: root.clone(),
            encryption_key: None,
        });
        assert!(naked.get("files/locked01.bin").await.is_err());
        tokio::fs::remove_dir_all(&root).await.ok();
    }
}
