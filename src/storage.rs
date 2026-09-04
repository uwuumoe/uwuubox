//! `ObjectStore` trait + local-FS and S3-compatible backends.
//!
//! Key layout: `files/<core><ext>`, `avatars/<uuid><ext>`. Local writes are
//! atomic (tmp file + rename, `0600`); deletes are idempotent so the expiry
//! sweeper can always finish the row delete.

use async_trait::async_trait;
use aws_sdk_s3::primitives::ByteStream;
use bytes::Bytes;
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use thiserror::Error;
use uuid::Uuid;

use crate::config::Env;

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
}

#[derive(Debug, Clone)]
pub struct S3Store {
    pub client: aws_sdk_s3::Client,
    pub bucket: String,
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

impl Store {
    pub async fn from_env(env: &Env) -> Result<Self, StorageError> {
        match env.storage_backend {
            crate::config::StorageBackend::Local => {
                std::fs::create_dir_all(&env.local_dir)
                    .map_err(|e| StorageError::Backend(e.to_string()))?;
                Ok(Self::Local(LocalStore {
                    root: env.local_dir.clone(),
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
                }))
            }
        }
    }

    pub async fn put(
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

    pub async fn get(&self, key: &str) -> Result<Bytes, StorageError> {
        match self {
            Self::Local(s) => s.get(key).await,
            Self::S3(s) => s.get(key).await,
        }
    }
    pub async fn get_range(
        &self,
        key: &str,
        offset: u64,
        len: u64,
    ) -> Result<Bytes, StorageError> {
        match self {
            Self::Local(s) => s.get_range(key, offset, len).await,
            Self::S3(s) => s.get_range(key, offset, len).await,
        }
    }


    pub async fn delete(&self, key: &str) -> Result<(), StorageError> {
        match self {
            Self::Local(s) => s.delete(key).await,
            Self::S3(s) => s.delete(key).await,
        }
    }
}
