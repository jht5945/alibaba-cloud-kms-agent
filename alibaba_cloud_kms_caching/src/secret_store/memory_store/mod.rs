mod cache;

use crate::output::GetSecretValueOutputDef;

use self::cache::Cache;

use super::{SecretStore, SecretStoreError};

use log::info;
use std::{
    num::NonZeroUsize,
    time::{Duration, Instant},
};

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
struct Key {
    secret_id: String,
    version_id: Option<String>,
    version_stage: Option<String>,
}

#[derive(Debug, Clone)]
struct GSVValue {
    value: GetSecretValueOutputDef,
    last_updated_at: Instant,
}

impl GSVValue {
    fn new(value: GetSecretValueOutputDef) -> Self {
        Self {
            value,
            last_updated_at: Instant::now(),
        }
    }
}

#[derive(Debug, Clone)]
/// In-memory secret store using an time and space bound cache
pub struct MemoryStore {
    gsv_cache: Cache<Key, GSVValue>,
    ttl: Duration,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new(NonZeroUsize::new(1000).unwrap(), Duration::from_secs(60))
    }
}

impl MemoryStore {
    /// Create a new memory store with the given max size and TTL
    pub fn new(max_size: NonZeroUsize, ttl: Duration) -> Self {
        Self {
            gsv_cache: Cache::new(max_size),
            ttl,
        }
    }
}

impl SecretStore for MemoryStore {
    fn get_secret_value(
        &self,
        secret_id: &str,
        version_id: Option<&str>,
        version_stage: Option<&str>,
    ) -> Result<GetSecretValueOutputDef, SecretStoreError> {
        match self.gsv_cache.get(&Key {
            secret_id: secret_id.to_string(),
            version_id: version_id.map(String::from),
            version_stage: version_stage.map(String::from),
        }) {
            Some(gsv) => {
                info!(
                    "Get from cache [{}, {:?}, {:?}], last updated elapsed: {:?}, ttl: {:?}, cache expired: {}",
                    secret_id,
                    version_id,
                    version_stage,
                    gsv.last_updated_at.elapsed(),
                    self.ttl,
                    gsv.last_updated_at.elapsed() > self.ttl
                );
                if gsv.last_updated_at.elapsed() > self.ttl {
                    Err(SecretStoreError::CacheExpired(Box::new(gsv.value.clone())))
                } else {
                    Ok(gsv.clone().value)
                }
            }
            None => Err(SecretStoreError::ResourceNotFound),
        }
    }

    fn write_secret_value(
        &mut self,
        secret_id: String,
        version_id: Option<String>,
        version_stage: Option<String>,
        data: GetSecretValueOutputDef,
    ) -> Result<(), SecretStoreError> {
        self.gsv_cache.insert(
            Key {
                secret_id: secret_id.to_string(),
                version_id,
                version_stage,
            },
            GSVValue::new(data),
        );

        Ok(())
    }
}
