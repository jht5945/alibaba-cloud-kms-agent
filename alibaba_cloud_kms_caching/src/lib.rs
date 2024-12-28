// #![warn(missing_docs)]
#![warn(missing_debug_implementations, rustdoc::missing_crate_level_docs)]

//! AWS Secrets Manager Caching Library

/// Error types
pub mod error;
/// Output of secret store
pub mod output;
/// Manages the lifecycle of cached secrets
pub mod secret_store;

use secret_store::SecretStoreError;

use crate::error::is_transient_error;
use alibaba_cloud_kms::{DescribeSecretRequest, GetSecretValueRequest, KmsClient};
use log::info;
use output::GetSecretValueOutputDef;
use secret_store::{MemoryStore, SecretStore};
use std::time::Instant;
use std::{error::Error, num::NonZeroUsize, time::Duration};
use tokio::sync::RwLock;

/// AWS Secrets Manager Caching client
#[derive(Debug)]
pub struct KmsCachingClient {
    /// Secrets Manager client to retrieve secrets.
    kms_client: KmsClient,
    /// A store used to cache secrets.
    store: RwLock<Box<dyn SecretStore>>,
    ignore_transient_errors: bool,
}

impl KmsCachingClient {
    /// Create a new caching client with in-memory store
    pub fn new(
        kms_client: KmsClient,
        max_size: NonZeroUsize,
        ttl: Duration,
        ignore_transient_errors: bool,
    ) -> Result<Self, SecretStoreError> {
        Ok(Self {
            kms_client,
            store: RwLock::new(Box::new(MemoryStore::new(max_size, ttl))),
            ignore_transient_errors,
        })
    }

    /// Retrieves the value of the secret from the specified version.
    pub async fn get_secret_value(
        &self,
        secret_id: &str,
        version_id: Option<&str>,
        version_stage: Option<&str>,
    ) -> Result<GetSecretValueOutputDef, Box<dyn Error>> {
        let read_lock = self.store.read().await;

        match read_lock.get_secret_value(secret_id, version_id, version_stage) {
            Ok(r) => Ok(r),
            Err(SecretStoreError::ResourceNotFound) => {
                drop(read_lock);
                info!(
                    "get_secret_value: ResourceNotFound [{}, {:?}, {:?}]",
                    secret_id, version_id, version_stage
                );
                Ok(self
                    .refresh_secret_value(secret_id, version_id, version_stage, None)
                    .await?)
            }
            Err(SecretStoreError::CacheExpired(cached_value)) => {
                drop(read_lock);
                info!(
                    "get_secret_value: CacheExpired [{}, {:?}, {:?}]",
                    secret_id, version_id, version_stage
                );
                Ok(self
                    .refresh_secret_value(secret_id, version_id, version_stage, Some(cached_value))
                    .await?)
            }
            Err(e) => Err(Box::new(e)),
        }
    }

    /// Refreshes the secret value through a GetSecretValue call to ASM
    async fn refresh_secret_value(
        &self,
        secret_id: &str,
        version_id: Option<&str>,
        version_stage: Option<&str>,
        cached_value: Option<Box<GetSecretValueOutputDef>>,
    ) -> Result<GetSecretValueOutputDef, Box<dyn Error>> {
        if let Some(ref cached_value) = cached_value {
            // The cache already had a value in it, we can quick-refresh it if the value is still current.
            if self
                .is_current(version_id, version_stage, cached_value.clone())
                .await?
            {
                // Re-up the entry freshness (TTL, cache rank) by writing the same data back to the cache.
                self.store.write().await.write_secret_value(
                    secret_id.to_owned(),
                    version_id.map(String::from),
                    version_stage.map(String::from),
                    *cached_value.clone(),
                )?;
                // Serve the cached value
                return Ok(*cached_value.clone());
            }
        }

        let start_get_secret_value = Instant::now();
        let get_secret_value_response_result = self
            .kms_client
            .get_secret_value(GetSecretValueRequest {
                secret_name: secret_id.to_owned(),
                version_id: version_id.map(String::from),
                version_stage: version_stage.map(String::from),
                ..Default::default()
            })
            .await;
        info!(
            "kms_client.get_secret_value({}, {:?}, {:?}), elapsed: {}ms",
            secret_id,
            version_id,
            version_stage,
            start_get_secret_value.elapsed().as_millis()
        );
        let result: GetSecretValueOutputDef = match get_secret_value_response_result {
            Ok(r) => r.into(),
            Err(e)
                if self.ignore_transient_errors
                    && is_transient_error(&e)
                    && cached_value.is_some() =>
            {
                info!(
                    "Return expired cache value for ignore_transient_errors is on, error: {}",
                    e
                );
                *cached_value.unwrap()
            }
            Err(e) => Err(e)?,
        };

        self.store.write().await.write_secret_value(
            secret_id.to_owned(),
            version_id.map(String::from),
            version_stage.map(String::from),
            result.clone(),
        )?;

        Ok(result)
    }

    /// Check if the value in the cache is still fresh enough to be served again
    async fn is_current(
        &self,
        version_id: Option<&str>,
        version_stage: Option<&str>,
        cached_value: Box<GetSecretValueOutputDef>,
    ) -> Result<bool, Box<dyn Error>> {
        let secret_id = cached_value.name.unwrap();
        let start_describe_secret = Instant::now();
        let describe_secret_response_result = self
            .kms_client
            .describe_secret(DescribeSecretRequest {
                secret_name: secret_id.clone(),
                ..Default::default()
            })
            .await;
        info!(
            "kms_client.describe_secret({}, {:?}, {:?}), elapsed: {}ms",
            secret_id,
            version_id,
            version_stage,
            start_describe_secret.elapsed().as_millis()
        );
        let _describe = match describe_secret_response_result {
            Ok(r) => r,
            Err(e) if self.ignore_transient_errors && is_transient_error(&e) => return Ok(true),
            Err(e) => Err(e)?,
        };

        // FIXME Alibaba Cloud cannot check secret via kms:DescribeSecret which like AWS
        Ok(false)
    }
}
