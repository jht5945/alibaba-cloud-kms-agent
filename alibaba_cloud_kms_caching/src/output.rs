use alibaba_cloud_kms::GetSecretValueResponse;
use iso8601_timestamp::Timestamp;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, TimestampSecondsWithFrac};
use std::time::SystemTime;

/// Exhaustive structure to store the secret value
///
/// We tried to De/Serialize the remote types using <https://serde.rs/remote-derive.html> but couldn't as the remote types are non_exhaustive,
/// which is a Rust limitation. We can remove this when aws sdk implements De/Serialize trait for the types.
#[serde_as]
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct GetSecretValueOutputDef {
    /// The friendly name of the secret.
    pub name: Option<String>,

    /// The unique identifier of this version of the secret.
    pub version_id: Option<String>,

    /// The decrypted secret value, if the secret value was originally provided as a string or through the Secrets Manager console.
    /// If this secret was created by using the console, then Secrets Manager stores the information as a JSON structure of key/value pairs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_data: Option<String>,

    /// A list of all the staging labels currently attached to this version of the secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_stages: Option<Vec<String>>,

    /// The date and time that this version of the secret was created. If you don't specify which version in <code>VersionId</code> or <code>VersionStage</code>, then Secrets Manager uses the <code>AWSCURRENT</code> version.
    #[serde_as(as = "Option<TimestampSecondsWithFrac<String>>")]
    pub created_date: Option<SystemTime>,
}

impl GetSecretValueOutputDef {
    /// Converts GetSecretValueOutput to GetSecretValueOutputDef
    pub fn new(input: GetSecretValueResponse) -> Self {
        Self {
            // arn: input.arn().map(|e| e.to_string()),
            name: Some(input.secret_name),
            version_id: Some(input.version_id),
            secret_data: Some(input.secret_data),
            created_date: Timestamp::parse(&input.create_time).map(Into::into),
            version_stages: Some(input.version_stages.version_stage),
        }
    }
}

impl From<GetSecretValueResponse> for GetSecretValueOutputDef {
    fn from(input: GetSecretValueResponse) -> Self {
        Self::new(input)
    }
}
