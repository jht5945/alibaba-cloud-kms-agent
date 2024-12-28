use crate::config::Config;
use crate::constants::MAX_REQ_TIME_SEC;
use std::env::VarError;
use std::fs;
use std::time::Duration;

use alibaba_cloud_kms::{AliyunClientError, CredentialConfig, KmsClient};
use std::env::var;

/// Helper to format error response body in Coral JSON 1.1 format.
#[doc(hidden)]
pub fn err_response(err_code: &str, msg: &str) -> String {
    if msg.is_empty() || err_code == "InternalFailure" {
        return String::from("{\"__type\":\"InternalFailure\"}");
    }
    format!("{{\"__type\":\"{err_code}\", \"message\":\"{msg}\"}}")
}

/// Helper function to get the SSRF token value.
#[doc(hidden)]
pub fn get_token(config: &Config) -> Result<String, Box<dyn std::error::Error>> {
    // Iterate through the env name list looking for the first variable set
    #[allow(clippy::redundant_closure)]
    let found = config
        .ssrf_env_variables()
        .iter()
        .map(|n| var(n))
        .filter_map(|r| r.ok())
        .next();
    if found.is_none() {
        return Err(Box::new(VarError::NotPresent));
    }
    let val = found.unwrap();

    // If the variable is not a reference to a file, just return the value.
    if !val.starts_with("file://") {
        return Ok(val);
    }

    // Read and return the contents of the file.
    let file = val.strip_prefix("file://").unwrap();
    Ok(fs::read_to_string(file)?.trim().to_string())
}

#[doc(hidden)]
pub use time_out_impl as time_out;

/// Helper function to get the time out setting for request processing.
#[doc(hidden)]
pub fn time_out_impl() -> Duration {
    Duration::from_secs(MAX_REQ_TIME_SEC)
}

/// Validates the provided configuration and creates an AWS Secrets Manager client
/// from the latest default AWS configuration.
#[doc(hidden)]
pub async fn validate_and_create_kms_client(
    config: &Config,
) -> Result<KmsClient, Box<dyn std::error::Error>> {
    let env_endpoint = var("KMS_ENDPOINT").ok();
    let endpoint = match (config.endpoint(), env_endpoint.as_deref()) {
        (Some(endpoint), _) => endpoint,
        (None, Some(endpoint)) => endpoint,
        _ => {
            return Err(AliyunClientError::InvalidRequest(
                "Endpoint is required".to_string(),
            ))?;
        }
    };

    let credential_config = match CredentialConfig::try_from_default(None)? {
        Some(credential_config) => credential_config,
        None => todo!("init credential_config failed."),
    };
    let kms_client = KmsClient::new(credential_config).endpoint(endpoint);
    Ok(kms_client)
}
