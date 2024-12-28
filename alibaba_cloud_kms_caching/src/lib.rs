// #![warn(missing_docs)]
#![warn(
    missing_debug_implementations,
    missing_docs,
    rustdoc::missing_crate_level_docs
)]

//! AWS Secrets Manager Caching Library

/// Error types
pub mod error;
/// Output of secret store
pub mod output;
/// Manages the lifecycle of cached secrets
pub mod secret_store;

use aws_sdk_secretsmanager::Client as SecretsManagerClient;
use error::is_transient_error;
use secret_store::SecretStoreError;

use output::GetSecretValueOutputDef;
use secret_store::{MemoryStore, SecretStore};
use std::{error::Error, num::NonZeroUsize, time::Duration};
use tokio::sync::RwLock;

/// AWS Secrets Manager Caching client
#[derive(Debug)]
pub struct SecretsManagerCachingClient {
    /// Secrets Manager client to retrieve secrets.
    asm_client: SecretsManagerClient,
    /// A store used to cache secrets.
    store: RwLock<Box<dyn SecretStore>>,
    ignore_transient_errors: bool,
}

impl SecretsManagerCachingClient {
    /// Create a new caching client with in-memory store
    ///
    /// # Arguments
    ///
    /// * `asm_client` - Initialized AWS SDK Secrets Manager client instance
    /// * `max_size` - Maximum size of the store.
    /// * `ttl` - Time-to-live of the secrets in the store.
    /// * `ignore_transient_errors` - Whether the client should serve cached data on transient refresh errors
    /// ```rust
    /// use aws_sdk_secretsmanager::Client as SecretsManagerClient;
    /// use aws_sdk_secretsmanager::{config::Region, Config};
    /// use aws_secretsmanager_caching::SecretsManagerCachingClient;
    /// use std::num::NonZeroUsize;
    /// use std::time::Duration;

    /// let asm_client = SecretsManagerClient::from_conf(
    /// Config::builder()
    ///     .behavior_version_latest()
    ///     .build(),
    /// );
    /// let client = SecretsManagerCachingClient::new(
    ///     asm_client,
    ///     NonZeroUsize::new(1000).unwrap(),
    ///     Duration::from_secs(300),
    ///     false,
    /// );
    /// ```
    pub fn new(
        asm_client: SecretsManagerClient,
        max_size: NonZeroUsize,
        ttl: Duration,
        ignore_transient_errors: bool,
    ) -> Result<Self, SecretStoreError> {
        Ok(Self {
            asm_client,
            store: RwLock::new(Box::new(MemoryStore::new(max_size, ttl))),
            ignore_transient_errors,
        })
    }

    /// Create a new caching client with in-memory store and the default AWS SDK client configuration
    ///
    /// # Arguments
    ///
    /// * `max_size` - Maximum size of the store.
    /// * `ttl` - Time-to-live of the secrets in the store.
    /// ```rust
    /// tokio_test::block_on(async {
    /// use aws_secretsmanager_caching::SecretsManagerCachingClient;
    /// use std::num::NonZeroUsize;
    /// use std::time::Duration;
    ///
    /// let client = SecretsManagerCachingClient::default(
    /// NonZeroUsize::new(1000).unwrap(),
    /// Duration::from_secs(300),
    /// ).await.unwrap();
    /// })
    /// ```
    // pub async fn default(max_size: NonZeroUsize, ttl: Duration) -> Result<Self, SecretStoreError> {
    //     let default_config = &aws_config::load_defaults(BehaviorVersion::latest()).await;
    //     let asm_builder = aws_sdk_secretsmanager::config::Builder::from(default_config)
    //         .interceptor(CachingLibraryInterceptor);
    //
    //     let asm_client = SecretsManagerClient::from_conf(asm_builder.build());
    //     Self::new(asm_client, max_size, ttl, false)
    // }

    /// Create a new caching client with in-memory store from an AWS SDK client builder
    ///
    /// # Arguments
    ///
    /// * `asm_builder` - AWS Secrets Manager SDK client builder.
    /// * `max_size` - Maximum size of the store.
    /// * `ttl` - Time-to-live of the secrets in the store.
    ///
    /// ```rust
    /// tokio_test::block_on(async {
    /// use aws_secretsmanager_caching::SecretsManagerCachingClient;
    /// use std::num::NonZeroUsize;
    /// use std::time::Duration;
    /// use aws_config::{BehaviorVersion, Region};

    /// let config = aws_config::load_defaults(BehaviorVersion::latest())
    /// .await
    /// .into_builder()
    /// .region(Region::from_static("us-west-2"))
    /// .build();

    /// let asm_builder = aws_sdk_secretsmanager::config::Builder::from(&config);

    /// let client = SecretsManagerCachingClient::from_builder(
    /// asm_builder,
    /// NonZeroUsize::new(1000).unwrap(),
    /// Duration::from_secs(300),
    /// false,
    /// )
    /// .await.unwrap();
    /// })
    /// ```
    // pub async fn from_builder(
    //     asm_builder: aws_sdk_secretsmanager::config::Builder,
    //     max_size: NonZeroUsize,
    //     ttl: Duration,
    //     ignore_transient_errors: bool,
    // ) -> Result<Self, SecretStoreError> {
    //     let asm_client = SecretsManagerClient::from_conf(
    //         asm_builder.interceptor(CachingLibraryInterceptor).build(),
    //     );
    //     Self::new(asm_client, max_size, ttl, ignore_transient_errors)
    // }

    /// Retrieves the value of the secret from the specified version.
    ///
    /// # Arguments
    ///
    /// * `secret_id` - The ARN or name of the secret to retrieve.
    /// * `version_id` - The version id of the secret version to retrieve.
    /// * `version_stage` - The staging label of the version of the secret to retrieve.
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
                Ok(self
                    .refresh_secret_value(secret_id, version_id, version_stage, None)
                    .await?)
            }
            Err(SecretStoreError::CacheExpired(cached_value)) => {
                drop(read_lock);
                Ok(self
                    .refresh_secret_value(secret_id, version_id, version_stage, Some(cached_value))
                    .await?)
            }
            Err(e) => Err(Box::new(e)),
        }
    }

    /// Refreshes the secret value through a GetSecretValue call to ASM
    ///
    /// # Arguments
    /// * `secret_id` - The ARN or name of the secret to retrieve.
    /// * `version_id` - The version id of the secret version to retrieve.
    /// * `version_stage` - The staging label of the version of the secret to retrieve.
    /// * `cached_value` - The value currently in the cache.
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

        let result: GetSecretValueOutputDef = match self
            .asm_client
            .get_secret_value()
            .secret_id(secret_id)
            .set_version_id(version_id.map(String::from))
            .set_version_stage(version_stage.map(String::from))
            .send()
            .await
        {
            Ok(r) => r.into(),
            Err(e)
                if self.ignore_transient_errors
                    && is_transient_error(&e)
                    && cached_value.is_some() =>
            {
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
    ///
    /// # Arguments
    /// * `version_id` - The version id of the secret version to retrieve.
    /// * `version_stage` - The staging label of the version of the secret to retrieve. Defaults to AWSCURRENT
    /// * `cached_value` - The value currently in the cache.
    ///
    /// # Returns
    /// * true if value can be reused, false if not
    async fn is_current(
        &self,
        version_id: Option<&str>,
        version_stage: Option<&str>,
        cached_value: Box<GetSecretValueOutputDef>,
    ) -> Result<bool, Box<dyn Error>> {
        let describe = match self
            .asm_client
            .describe_secret()
            .secret_id(cached_value.arn.unwrap())
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) if self.ignore_transient_errors && is_transient_error(&e) => return Ok(true),
            Err(e) => Err(e)?,
        };

        let real_vids_to_stages = match describe.version_ids_to_stages() {
            Some(vids_to_stages) => vids_to_stages,
            // Secret has no version Ids
            None => return Ok(false),
        };

        #[allow(clippy::unnecessary_unwrap)]
        // Only version id is given, then check if the version id still exists
        if version_id.is_some() && version_stage.is_none() {
            return Ok(real_vids_to_stages
                .iter()
                .any(|(k, _)| k.eq(version_id.unwrap())));
        }

        // If no version id is given, use the cached version id
        let version_id = match version_id {
            Some(id) => id.to_owned(),
            None => cached_value.version_id.clone().unwrap(),
        };

        // If no version stage was passed, check AWSCURRENT
        let version_stage = match version_stage {
            Some(v) => v.to_owned(),
            None => "AWSCURRENT".to_owned(),
        };

        // True if the version id and version stage match real_vids_to_stages in AWS Secrets Manager
        Ok(real_vids_to_stages
            .iter()
            .any(|(k, v)| k.eq(&version_id) && v.contains(&version_stage)))
    }
}
