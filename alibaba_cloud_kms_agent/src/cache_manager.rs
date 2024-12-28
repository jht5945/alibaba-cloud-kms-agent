use crate::error::HttpError;
use crate::utils::err_response;
use aws_sdk_secretsmanager::error::ProvideErrorMetadata;
use aws_sdk_secretsmanager::operation::describe_secret::DescribeSecretError;
use aws_sdk_secretsmanager::operation::get_secret_value::GetSecretValueError;
use alibaba_cloud_kms_caching::SecretsManagerCachingClient;
use aws_smithy_runtime_api::client::orchestrator::HttpResponse;
use aws_smithy_runtime_api::client::result::SdkError;
use log::error;

use crate::config::Config;

/// Wrapper around the caching library
///
/// Used to cache and retrieve secrets.
#[derive(Debug)]
pub struct CacheManager(SecretsManagerCachingClient);

// Use either the real Secrets Manager client or the stub for testing
#[doc(hidden)]
use crate::utils::validate_and_create_asm_client as asm_client;

/// Wrapper around the caching library
///
/// Used to cache and retrieve secrets.
impl CacheManager {
    /// Create a new CacheManager. For simplicity I'm propagating the errors back up for now.
    pub async fn new(cfg: &Config) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self(SecretsManagerCachingClient::new(
            asm_client(cfg).await?,
            cfg.cache_size(),
            cfg.ttl(),
            cfg.ignore_transient_errors(),
        )?))
    }

    /// Fetch a secret from the cache.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the secret to fetch.
    /// * `version` - The version of the secret to fetch.
    /// * `label` - The label of the secret to fetch.
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - The value of the secret.
    /// * `Err((u16, String))` - The error code and message.
    ///
    /// # Errors
    ///
    /// * `SerializationError` - The error returned from the serde_json::to_string method.
    ///
    /// # Example
    ///
    /// ```
    /// let cache_manager = CacheManager::new().await.unwrap();
    /// let value = cache_manager.fetch("my-secret", None, None).unwrap();
    /// ```
    pub async fn fetch(
        &self,
        secret_id: &str,
        version: Option<&str>,
        label: Option<&str>,
    ) -> Result<String, HttpError> {
        // Read the secret from the cache or fetch it over the network.
        let found = match self.0.get_secret_value(secret_id, version, label).await {
            Ok(value) => value,
            Err(e) if e.is::<SdkError<GetSecretValueError, HttpResponse>>() => {
                let (code, msg, status) = svc_err::<GetSecretValueError>(e)?;
                return Err(HttpError(status, err_response(&code, &msg)));
            }
            Err(e) if e.is::<SdkError<DescribeSecretError, HttpResponse>>() => {
                let (code, msg, status) = svc_err::<DescribeSecretError>(e)?;
                return Err(HttpError(status, err_response(&code, &msg)));
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

/// Private helper to extract the error code, message, and status code from an SDK exception.
///
/// Downcasts the exception into the specific SDK exception type and retrieves
/// the excpetion code (e.g. ResourceNotFoundException), error message, and http
/// status code or returns an error if the fields are not present. Timeout and
/// network errors are also translated to appropriate error codes.
///
/// # Returns
///
/// * `Ok((code, msg, status))` - A tuple of error code, error message, and http status code.
/// * `Err((500, InternalFailureString))` - An internal service error.
#[doc(hidden)]
fn svc_err<S>(err: Box<dyn std::error::Error>) -> Result<(String, String, u16), HttpError>
where
    S: ProvideErrorMetadata + std::error::Error + 'static,
{
    let sdk_err = err
        .downcast_ref::<SdkError<S, HttpResponse>>()
        .ok_or(int_err())?;

    // Get the error metadata and translate timeouts to 504 and network errors to 502
    let err_meta = match sdk_err {
        SdkError::ServiceError(serr) => serr.err().meta(),
        SdkError::DispatchFailure(derr) if derr.is_timeout() => {
            return Ok(("TimeoutError".into(), "Timeout".into(), 504));
        }
        SdkError::TimeoutError(_) => {
            return Ok(("TimeoutError".into(), "Timeout".into(), 504));
        }
        SdkError::DispatchFailure(derr) if derr.is_io() => {
            return Ok(("ConnectionError".into(), "Read Error".into(), 502));
        }
        SdkError::ResponseError(_) => {
            return Ok(("ConnectionError".into(), "Response Error".into(), 502));
        }
        _ => return Err(int_err()),
    };

    let code = err_meta.code().ok_or(int_err())?;
    let msg = err_meta.message().ok_or(int_err())?;
    let status = sdk_err.raw_response().ok_or(int_err())?.status().as_u16();

    Ok((code.into(), msg.into(), status))
}
