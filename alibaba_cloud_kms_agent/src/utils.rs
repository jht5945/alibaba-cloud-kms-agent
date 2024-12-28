use crate::config::Config;
use crate::constants::{APPNAME, MAX_REQ_TIME_SEC, VERSION};
use aws_sdk_secretsmanager::config::interceptors::BeforeTransmitInterceptorContextMut;
use aws_sdk_secretsmanager::config::{ConfigBag, Intercept, RuntimeComponents};
use aws_sdk_secretsmanager::Client as SecretsManagerClient;
use std::env::VarError;
use std::fs;
use std::time::Duration;

use std::env::var; // Use the real std::env::var

/// Helper to format error response body in Coral JSON 1.1 format.
///
/// Callers need to pass in the error code (e.g.  InternalFailure,
/// InvalidParameterException, ect.) and the error message. This function will
/// then format a response body in JSON 1.1 format.
///
/// # Arguments
///
/// * `err_code` - The modeled exception name or InternalFailure for 500s.
/// * `msg` - The optional error message or "" for InternalFailure.
///
/// # Returns
///
/// * `String` - The JSON 1.1 response body.
///
/// # Example
///
/// ```
/// assert_eq!(err_response("InternalFailure", ""), "{\"__type\":\"InternalFailure\"}");
/// assert_eq!(
///     err_response("ResourceNotFoundException", "Secrets Manager can't find the specified secret."),
///     "{\"__type\":\"ResourceNotFoundException\",\"message\":\"Secrets Manager can't find the specified secret.\"}"
/// );
/// ```
#[doc(hidden)]
pub fn err_response(err_code: &str, msg: &str) -> String {
    if msg.is_empty() || err_code == "InternalFailure" {
        return String::from("{\"__type\":\"InternalFailure\"}");
    }
    format!("{{\"__type\":\"{err_code}\", \"message\":\"{msg}\"}}")
}

/// Helper function to get the SSRF token value.
///
/// Reads the SSRF token from the configured env variable. If the env variable
/// is a reference to a file (namely file://FILENAME), the data is read in from
/// that file.
///
/// # Arguments
///
/// * `config` - The configuration options for the daemon.
///
/// # Returns
///
/// * `Ok(String)` - The SSRF token value.
/// * `Err(Error)` - Error indicating that the variable is not set or could not be read.
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
///
/// # Returns
///
/// * `Durration` - How long to wait before canceling the operation.
#[doc(hidden)]
pub fn time_out_impl() -> Duration {
    Duration::from_secs(MAX_REQ_TIME_SEC)
}

/// Validates the provided configuration and creates an AWS Secrets Manager client
/// from the latest default AWS configuration.
///
/// # Arguments
///
/// * `config` - A reference to a `Config` object containing the necessary configuration
///   parameters for creating the AWS Secrets Manager client.
///
/// # Returns
///
/// * `Ok(SecretsManagerClient)` - An AWS Secrets Manager client if the credentials are valid.
/// * `Err(Box<dyn std::error::Error>)` if there is an error creating the Secrets Manager client
///   or validating the AWS credentials.
#[doc(hidden)]
pub async fn validate_and_create_asm_client(
    config: &Config,
) -> Result<SecretsManagerClient, Box<dyn std::error::Error>> {
    use aws_config::{BehaviorVersion, Region};
    use alibaba_cloud_kms_caching::error::is_transient_error;

    let default_config = &aws_config::load_defaults(BehaviorVersion::latest()).await;
    let mut asm_builder = aws_sdk_secretsmanager::config::Builder::from(default_config)
        .interceptor(AgentModifierInterceptor);
    let mut sts_builder = aws_sdk_sts::config::Builder::from(default_config);

    if let Some(region) = config.region() {
        asm_builder.set_region(Some(Region::new(region.clone())));
        sts_builder.set_region(Some(Region::new(region.clone())));
    }

    // Validate the region and credentials first
    let sts_client = aws_sdk_sts::Client::from_conf(sts_builder.build());
    match sts_client.get_caller_identity().send().await {
        Ok(_) => (),
        Err(e) if config.ignore_transient_errors() && is_transient_error(&e) => (),
        Err(e) => Err(e)?,
    };

    Ok(aws_sdk_secretsmanager::Client::from_conf(
        asm_builder.build(),
    ))
}

/// SDK interceptor to append the agent name and version to the User-Agent header for CloudTrail records.
#[doc(hidden)]
#[derive(Debug)]
pub struct AgentModifierInterceptor;

/// SDK interceptor to append the agent name and version to the User-Agent header for CloudTrail records.
///
/// This interceptor adds the agent name and version to the User-Agent header
/// of outbound Secrets Manager SDK requests.
#[doc(hidden)]
impl Intercept for AgentModifierInterceptor {
    fn name(&self) -> &'static str {
        "AgentModifierInterceptor"
    }

    fn modify_before_signing(
        &self,
        context: &mut BeforeTransmitInterceptorContextMut<'_>,
        _runtime_components: &RuntimeComponents,
        _cfg: &mut ConfigBag,
    ) -> Result<(), aws_sdk_secretsmanager::error::BoxError> {
        let request = context.request_mut();
        let agent = request.headers().get("user-agent").unwrap_or_default(); // Get current agent
        let full_agent = format!("{agent} {APPNAME}/{}", VERSION.unwrap_or("0.0.0"));
        request.headers_mut().insert("user-agent", full_agent); // Overwrite header.

        Ok(())
    }
}
