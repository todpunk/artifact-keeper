//! Filesystem storage backend.

use async_trait::async_trait;
use bytes::Bytes;
use std::path::PathBuf;
use tokio::fs;
use tokio::io::AsyncWriteExt;

use super::StorageBackend;
use crate::error::{AppError, Result};

/// Filesystem-based storage backend
pub struct FilesystemStorage {
    base_path: PathBuf,
}

impl FilesystemStorage {
    /// Create new filesystem storage
    pub fn new(base_path: impl Into<PathBuf>) -> Self {
        Self {
            base_path: base_path.into(),
        }
    }

    /// Get full path for a key (using first 2 chars as subdirectory for distribution).
    ///
    /// All non-`Normal` path components (e.g. `..`, leading `/`) are stripped before
    /// building the final path so that a user-controlled key can never escape the
    /// storage base directory.
    fn key_to_path(&self, key: &str) -> PathBuf {
        // Strip "..", absolute-path markers, and any other non-Normal components
        // to prevent path traversal out of the storage base directory.
        let sanitized: PathBuf = std::path::Path::new(key)
            .components()
            .filter(|c| matches!(c, std::path::Component::Normal(_)))
            .collect();
        let sanitized_str = sanitized.to_string_lossy();
        let prefix = &sanitized_str[..2.min(sanitized_str.len())];
        self.base_path.join(prefix).join(&sanitized)
    }
}

#[async_trait]
impl StorageBackend for FilesystemStorage {
    async fn put(&self, key: &str, content: Bytes) -> Result<()> {
        let path = self.key_to_path(key);

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }

        // Write content
        let mut file = fs::File::create(&path).await?;
        file.write_all(&content).await?;
        file.sync_all().await?;

        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Bytes> {
        let path = self.key_to_path(key);
        let content = fs::read(&path)
            .await
            .map_err(|e| AppError::Storage(format!("Failed to read {}: {}", key, e)))?;
        Ok(Bytes::from(content))
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        let path = self.key_to_path(key);
        Ok(path.exists())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let path = self.key_to_path(key);
        fs::remove_file(&path)
            .await
            .map_err(|e| AppError::Storage(format!("Failed to delete {}: {}", key, e)))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_filesystem_storage() {
        let storage = FilesystemStorage::new("/tmp/test-storage");
        assert_eq!(storage.base_path, PathBuf::from("/tmp/test-storage"));
    }

    #[test]
    fn test_new_from_pathbuf() {
        let path = PathBuf::from("/var/data/artifacts");
        let storage = FilesystemStorage::new(path.clone());
        assert_eq!(storage.base_path, path);
    }

    #[test]
    fn test_key_to_path_normal_key() {
        let storage = FilesystemStorage::new("/data");
        let path = storage.key_to_path("abcdef1234567890");
        // First 2 chars = "ab", used as subdirectory
        assert_eq!(path, PathBuf::from("/data/ab/abcdef1234567890"));
    }

    #[test]
    fn test_key_to_path_sha256_hash() {
        let storage = FilesystemStorage::new("/storage");
        let key = "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9";
        let path = storage.key_to_path(key);
        assert_eq!(path, PathBuf::from(format!("/storage/91/{}", key)));
    }

    #[test]
    fn test_key_to_path_short_key() {
        let storage = FilesystemStorage::new("/data");
        // Key shorter than 2 chars: uses entire key as prefix
        let path = storage.key_to_path("a");
        assert_eq!(path, PathBuf::from("/data/a/a"));
    }

    #[test]
    fn test_key_to_path_two_char_key() {
        let storage = FilesystemStorage::new("/data");
        let path = storage.key_to_path("ab");
        assert_eq!(path, PathBuf::from("/data/ab/ab"));
    }

    #[test]
    fn test_key_to_path_distributes_across_dirs() {
        let storage = FilesystemStorage::new("/data");
        let path1 = storage.key_to_path("aa1234");
        let path2 = storage.key_to_path("bb5678");
        // Different prefix subdirectories
        assert_ne!(path1.parent().unwrap(), path2.parent().unwrap());
    }

    #[test]
    fn test_key_to_path_same_prefix_same_dir() {
        let storage = FilesystemStorage::new("/data");
        let path1 = storage.key_to_path("ab1111");
        let path2 = storage.key_to_path("ab2222");
        // Same prefix = same subdirectory
        assert_eq!(path1.parent().unwrap(), path2.parent().unwrap());
    }

    #[tokio::test]
    async fn test_put_and_get() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = FilesystemStorage::new(temp_dir.path());

        let key = "abcdef1234567890";
        let content = Bytes::from_static(b"hello world");

        storage.put(key, content.clone()).await.unwrap();

        let retrieved = storage.get(key).await.unwrap();
        assert_eq!(retrieved, content);
    }

    #[tokio::test]
    async fn test_exists() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = FilesystemStorage::new(temp_dir.path());

        let key = "abcdef1234567890";
        assert!(!storage.exists(key).await.unwrap());

        storage.put(key, Bytes::from_static(b"data")).await.unwrap();
        assert!(storage.exists(key).await.unwrap());
    }

    #[tokio::test]
    async fn test_delete() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = FilesystemStorage::new(temp_dir.path());

        let key = "abcdef1234567890";
        storage.put(key, Bytes::from_static(b"data")).await.unwrap();
        assert!(storage.exists(key).await.unwrap());

        storage.delete(key).await.unwrap();
        assert!(!storage.exists(key).await.unwrap());
    }

    #[tokio::test]
    async fn test_get_nonexistent_key() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = FilesystemStorage::new(temp_dir.path());

        let result = storage.get("nonexistent-key1234").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_delete_nonexistent_key() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = FilesystemStorage::new(temp_dir.path());

        let result = storage.delete("nonexistent-key1234").await;
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Path traversal protection in key_to_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_key_to_path_dotdot_stays_inside_base() {
        let storage = FilesystemStorage::new("/data");
        let path = storage.key_to_path("maven/../../etc/passwd");
        // ".." components must be stripped; path must remain under /data
        assert!(
            path.starts_with("/data"),
            "traversal key must not escape base_path, got {:?}",
            path
        );
    }

    #[test]
    fn test_key_to_path_absolute_key_stays_inside_base() {
        let storage = FilesystemStorage::new("/data");
        let path = storage.key_to_path("/etc/shadow");
        // Leading "/" (RootDir component) must be stripped
        assert!(
            path.starts_with("/data"),
            "absolute key must not escape base_path, got {:?}",
            path
        );
    }

    #[test]
    fn test_key_to_path_pure_traversal_stays_inside_base() {
        let storage = FilesystemStorage::new("/data");
        // Mimics the AKSEC-2026-013 PoC key after Axum percent-decoding
        let path = storage.key_to_path("maven/../../../../../tmp/aksec-2026-013-pwned.sha1");
        assert!(
            path.starts_with("/data"),
            "PoC traversal key must not escape base_path, got {:?}",
            path
        );
    }

    #[tokio::test]
    async fn test_traversal_write_stays_inside_storage() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = FilesystemStorage::new(temp_dir.path());

        // Before the fix this would write to a path outside temp_dir; after the
        // fix the sanitised key must resolve inside temp_dir.
        let path = storage.key_to_path("../../escape.txt");
        assert!(
            path.starts_with(temp_dir.path()),
            "key_to_path must stay within base_path, got {:?}",
            path
        );

        // The write should succeed (sanitised location inside temp_dir)
        storage
            .put("../../escape.txt", Bytes::from_static(b"pwned"))
            .await
            .unwrap();

        // And the content must be readable via the same key
        let content = storage.get("../../escape.txt").await.unwrap();
        assert_eq!(content, Bytes::from_static(b"pwned"));
    }

    #[tokio::test]
    async fn test_put_overwrites_existing() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = FilesystemStorage::new(temp_dir.path());

        let key = "abcdef1234567890";
        storage
            .put(key, Bytes::from_static(b"original"))
            .await
            .unwrap();
        storage
            .put(key, Bytes::from_static(b"updated"))
            .await
            .unwrap();

        let retrieved = storage.get(key).await.unwrap();
        assert_eq!(retrieved, Bytes::from_static(b"updated"));
    }
}
