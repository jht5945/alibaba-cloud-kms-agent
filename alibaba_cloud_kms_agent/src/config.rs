use crate::constants::EMPTY_ENV_LIST_MSG;
use crate::constants::{BAD_MAX_CONN_MSG, BAD_PREFIX_MSG, EMPTY_SSRF_LIST_MSG};
use crate::constants::{DEFAULT_MAX_CONNECTIONS, GENERIC_CONFIG_ERR_MSG};
use crate::constants::{INVALID_CACHE_SIZE_ERR_MSG, INVALID_HTTP_PORT_ERR_MSG};
use crate::constants::{INVALID_LOG_LEVEL_ERR_MSG, INVALID_TTL_SECONDS_ERR_MSG};
use config::Config as ConfigLib;
use config::File;
use serde_derive::Deserialize;
use std::num::NonZeroUsize;
use std::ops::Range;
use std::str::FromStr;
use std::time::Duration;

const DEFAULT_LOG_LEVEL: &str = "info";
const DEFAULT_HTTP_PORT: &str = "2773";
const DEFAULT_TTL_SECONDS: &str = "300";
const DEFAULT_CACHE_SIZE: &str = "1000";
const DEFAULT_SSRF_HEADERS: [&str; 2] = ["X-Aws-Parameters-Secrets-Token", "X-Vault-Token"];
const DEFAULT_SSRF_ENV_VARIABLES: [&str; 6] = [
    "AWS_TOKEN",
    "AWS_SESSION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "ALIBABA_CLOUD_TOKEN",
    "ALIBABA_CLOUD_SESSION_TOKEN",
    "ALIBABA_CLOUD_CONTAINER_AUTHORIZATION_TOKEN",
];
const DEFAULT_PATH_PREFIX: &str = "/v1/";
const DEFAULT_IGNORE_TRANSIENT_ERRORS: bool = true;

const DEFAULT_ENDPOINT: Option<String> = None;

/// Private struct used to deserialize configurations from the file.
#[doc(hidden)]
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)] // We want to error out when file has misspelled or unknown configurations.
struct ConfigFile {
    log_level: String,
    http_port: String,
    ttl_seconds: String,
    cache_size: String,
    ssrf_headers: Vec<String>,
    ssrf_env_variables: Vec<String>,
    path_prefix: String,
    max_conn: String,
    endpoint: Option<String>,
    ignore_transient_errors: bool,
}

/// The log levels supported by the daemon.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq, Copy)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
    None,
}

/// Returns the log level if the provided `log_level` string is valid.
/// Returns Err if it's invalid.
impl FromStr for LogLevel {
    type Err = String;
    fn from_str(log_level: &str) -> Result<Self, String> {
        match log_level.to_lowercase().as_str() {
            "debug" => Ok(LogLevel::Debug),
            "info" => Ok(LogLevel::Info),
            "warn" => Ok(LogLevel::Warn),
            "error" => Ok(LogLevel::Error),
            "none" => Ok(LogLevel::None),
            _ => Err(String::from(INVALID_LOG_LEVEL_ERR_MSG)),
        }
    }
}

/// The contains the configurations that are used by the daemon.
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    /// The level of logging the agent provides ie. debug, info, warn, error or none.
    log_level: LogLevel,

    /// The port for the local HTTP server.
    http_port: u16,

    /// The `time to live` of a secret
    ttl: Duration,

    /// Maximum number secrets that can be stored in the cache.
    cache_size: NonZeroUsize,

    /// A list of request headers which will be checked in order for the SSRF
    /// token. Contains at least one request header.
    ssrf_headers: Vec<String>,

    /// The list of the environment variable names to search through for the SSRF token.
    ssrf_env_variables: Vec<String>,

    /// The prefix for path based requests.
    path_prefix: String,

    /// The maximum number of simultaneous connections.
    max_conn: usize,

    /// The KMS endpoint that will be used to send the KMS request to.
    endpoint: Option<String>,

    /// Whether the agent should serve cached data on transient refresh errors
    ignore_transient_errors: bool,
}

/// The default configuration options.
impl Default for Config {
    fn default() -> Self {
        Config::new(None).expect(GENERIC_CONFIG_ERR_MSG)
    }
}

/// The contains the configurations that are used by the daemon.
impl Config {
    /// Initialize the configuation using the optional configuration file.
    pub fn new(file_path: Option<&str>) -> Result<Config, Box<dyn std::error::Error>> {
        // Setting default configurations
        let mut config = ConfigLib::builder()
            .set_default("log_level", DEFAULT_LOG_LEVEL)?
            .set_default("http_port", DEFAULT_HTTP_PORT)?
            .set_default("ttl_seconds", DEFAULT_TTL_SECONDS)?
            .set_default("cache_size", DEFAULT_CACHE_SIZE)?
            .set_default::<&str, Vec<String>>(
                "ssrf_headers",
                DEFAULT_SSRF_HEADERS.map(String::from).to_vec(),
            )?
            .set_default::<&str, Vec<String>>(
                "ssrf_env_variables",
                DEFAULT_SSRF_ENV_VARIABLES.map(String::from).to_vec(),
            )?
            .set_default("path_prefix", DEFAULT_PATH_PREFIX)?
            .set_default("max_conn", DEFAULT_MAX_CONNECTIONS)?
            .set_default("endpoint", DEFAULT_ENDPOINT)?
            .set_default("ignore_transient_errors", DEFAULT_IGNORE_TRANSIENT_ERRORS)?;

        // Merge the config overrides onto the default configurations, if provided.
        config = match file_path {
            Some(file_path_str) => config.add_source(File::with_name(file_path_str)),
            None => config,
        };

        Config::build(config.build()?.try_deserialize()?)
    }

    /// The level of logging the agent provides ie. debug, info, warn, error or none
    pub fn log_level(&self) -> LogLevel {
        self.log_level
    }

    /// The port for the local HTTP server to listen for incoming requests.
    pub fn http_port(&self) -> u16 {
        self.http_port
    }

    /// The `time to live` of a secret in the cache in seconds.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Maximum number secrets that can be stored in the cache
    pub fn cache_size(&self) -> NonZeroUsize {
        self.cache_size
    }

    /// A list of request headers which will be checked for the SSRF token (can not be empty).
    pub fn ssrf_headers(&self) -> Vec<String> {
        self.ssrf_headers.clone()
    }

    /// The name of the environment variable containing the SSRF token.
    pub fn ssrf_env_variables(&self) -> Vec<String> {
        self.ssrf_env_variables.clone()
    }

    /// The prefix for path based requests (must begin with /).
    pub fn path_prefix(&self) -> String {
        self.path_prefix.clone()
    }

    /// The maximum number of simultaneous connections (1000 max).
    pub fn max_conn(&self) -> usize {
        self.max_conn
    }

    /// The KMS enpoint that will be used to send the KMS request to.
    pub fn endpoint(&self) -> Option<&String> {
        self.endpoint.as_ref()
    }

    /// Whether the client should serve cached data on transient refresh errors
    pub fn ignore_transient_errors(&self) -> bool {
        self.ignore_transient_errors
    }

    /// Private helper that fills in the Config instance from the specified
    /// config overrides (or defaults).
    #[doc(hidden)]
    fn build(config_file: ConfigFile) -> Result<Config, Box<dyn std::error::Error>> {
        let config = Config {
            // Configurations that are allowed to be overridden.
            log_level: LogLevel::from_str(config_file.log_level.as_str())?,
            http_port: parse_num::<u16>(
                &config_file.http_port,
                INVALID_HTTP_PORT_ERR_MSG,
                None,
                Some(1..1024),
            )?,
            ttl: Duration::from_secs(parse_num::<u64>(
                &config_file.ttl_seconds,
                INVALID_TTL_SECONDS_ERR_MSG,
                Some(0..3601),
                None,
            )?),
            cache_size: match NonZeroUsize::new(parse_num::<usize>(
                &config_file.cache_size,
                INVALID_CACHE_SIZE_ERR_MSG,
                Some(0..1001),
                None,
            )?) {
                Some(x) => x,
                None => Err(INVALID_CACHE_SIZE_ERR_MSG)?,
            },
            ssrf_headers: config_file.ssrf_headers,
            ssrf_env_variables: config_file.ssrf_env_variables,
            path_prefix: config_file.path_prefix,
            max_conn: parse_num::<usize>(
                &config_file.max_conn,
                BAD_MAX_CONN_MSG,
                Some(1..1001),
                None,
            )?,
            endpoint: config_file.endpoint,
            ignore_transient_errors: config_file.ignore_transient_errors,
        };

        // Additional validations.
        if config.ssrf_headers.is_empty() {
            Err(EMPTY_SSRF_LIST_MSG)?;
        }
        if config.ssrf_env_variables.is_empty() {
            Err(EMPTY_ENV_LIST_MSG)?;
        }
        if !config.path_prefix.starts_with('/') {
            Err(BAD_PREFIX_MSG)?;
        }

        Ok(config)
    }
}

/// Private helper to convert a string to number and perform range checks, returning a custom error on failure.
#[doc(hidden)]
fn parse_num<T>(
    str_val: &str,
    msg: &str,
    pos_range: Option<Range<T>>,
    neg_range: Option<Range<T>>,
) -> Result<T, Box<dyn std::error::Error>>
where
    T: PartialOrd + Sized + std::str::FromStr,
{
    let val = match str_val.parse::<T>() {
        Ok(x) => x,
        _ => Err(msg)?,
    };
    if let Some(rng) = pos_range {
        if !rng.contains(&val) {
            Err(msg)?;
        }
    }
    if let Some(rng) = neg_range {
        if rng.contains(&val) {
            Err(msg)?;
        }
    }

    Ok(val)
}
