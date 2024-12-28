use crate::error::HttpError;
use crate::utils::err_response;
use alibaba_cloud_kms::AliyunClientError;
use alibaba_cloud_kms_caching::KmsCachingClient;
use log::error;

use crate::config::Config;

/// Wrapper around the caching library
///
/// Used to cache and retrieve secrets.
#[derive(Debug)]
pub struct CacheManager(KmsCachingClient);

// Use either the real Secrets Manager client or the stub for testing
#[doc(hidden)]
use crate::utils::validate_and_create_kms_client as kms_client;

/// Wrapper around the caching library
///
/// Used to cache and retrieve secrets.
impl CacheManager {
    /// Create a new CacheManager. For simplicity I'm propagating the errors back up for now.
    pub async fn new(cfg: &Config) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self(KmsCachingClient::new(
            kms_client(cfg).await?,
            cfg.cache_size(),
            cfg.ttl(),
            cfg.ignore_transient_errors(),
        )?))
    }

    /// Fetch a secret from the cache.
    pub async fn fetch(
        &self,
        secret_id: &str,
        version: Option<&str>,
        label: Option<&str>,
    ) -> Result<String, HttpError> {
        // Read the secret from the cache or fetch it over the network.
        let found = match self.0.get_secret_value(secret_id, version, label).await {
            Ok(value) => value,
            Err(e) if e.is::<AliyunClientError>() => {
                let aliyun_client_error: &AliyunClientError = e.downcast_ref().unwrap();
                return Err(to_http_error(aliyun_client_error));
            }
            Err(e) => {
                error!("Internal error for {secret_id} - {:?}", e);
                return Err(int_err());
            }
        };

        // Serialize and return the value
        match serde_json::to_string(&found) {
            Ok(value) => Ok(value),
            _ => {
                error!("Serialization error for {secret_id}");
                Err(int_err())?
            }
        }
    }
}

/// Private helper to format in internal service error response.
#[doc(hidden)]
fn int_err() -> HttpError {
    HttpError(500, err_response("InternalFailure", ""))
}

#[doc(hidden)]
fn to_http_error(aliyun_client_error: &AliyunClientError) -> HttpError {
    match aliyun_client_error {
        AliyunClientError::Reqwest(e) => HttpError(
            400,
            err_response("InvalidRequest", &format!("Invalid reqwest: {}", e)),
        ),
        AliyunClientError::InvalidHeader(e) => HttpError(
            400,
            err_response("InvalidRequest", &format!("Invalid reqwest header: {}", e)),
        ),
        AliyunClientError::InvalidRequest(e) => HttpError(400, err_response("InvalidRequest", e)),
        AliyunClientError::InvalidResponse {
            request_id,
            error_code,
            error_message,
        } => {
            // FIXME check more error codes @see alibaba_cloud_kms_caching/src/error.rs
            let status = match error_code.as_str() {
                error if error.contains("Temporary") || error.contains("InternalError") => 500,
                _ => 400,
            };
            HttpError(
                status,
                err_response(
                    error_code,
                    &format!("Request: {}, message: {}", request_id, error_message),
                ),
            )
        }
    }
}
