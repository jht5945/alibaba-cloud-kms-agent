use log::{error, info};
use tokio::net::TcpListener;

use std::env;
use std::net::SocketAddr;
mod error;
mod parse;

mod cache_manager;
mod server;
use server::Server;
mod config;
mod constants;
mod logging;
mod utils;

use config::Config;
use constants::VERSION;
use logging::init_logger;
use utils::get_token;

/// Main entry point for the daemon.
///
/// # Returns
///
/// * `Ok(())` - Never retuned.
/// * `Box<dyn std::error::Error>>` - Retruned for errors initializing the agent.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    run(env::args(), &report, &forever).await
}

/// Private helper to report startup and the listener port.
///
/// The private helper just prints the startup info. In unit tests a different
/// helper is used to report back the server port.
///
/// # Arguments
///
/// * `addr` - The socket address on which the daemon is listening.
///
/// # Example
///
/// ```
/// use std::net::SocketAddr;
/// report( &SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 2773) );
/// ```
#[doc(hidden)]
fn report(addr: &SocketAddr) {
    let start_msg = format!(
        "Agent/{} listening on http://{}",
        VERSION.unwrap_or("0.0.0"),
        addr
    );
    println!("{start_msg}");
    info!("{start_msg}");
}

/// Private helper used to run the server fovever.
///
/// This helper is used when the server is started through the main entry point.
/// In unit tests a different helper is used to signal shutdown.
///
/// # Returns
///
/// * bool - Always returns false so the server never shuts down.
///
/// # Example
///
/// ```
/// assert_eq!(forever(), false);
/// ```
#[doc(hidden)]
fn forever() -> bool {
    false
}

/// Private helper do the main body of the server.
///
/// # Arguments
///
/// * `args` - The command line arguments.
/// * `report` - A call back used to report startup and the listener port.
/// * `end` - A call back used to signal shut down.
/// # Returns
///
/// * `Ok(())` - Never retuned when started by the main entry point.
/// * `Box<dyn std::error::Error>` - Retruned for errors initializing the agent.
#[doc(hidden)]
async fn run<S: FnMut(&SocketAddr), E: FnMut() -> bool>(
    args: impl IntoIterator<Item = String>,
    mut report: S,
    mut end: E,
) -> Result<(), Box<dyn std::error::Error>> {
    let (cfg, listener) = init(args).await;
    let addr = listener.local_addr()?;
    let svr = Server::new(listener, &cfg).await?;

    report(&addr); // Report the port used.

    // Spawn a handler for each incomming request.
    loop {
        // Report errors on accept.
        if let Err(msg) = svr.serve_request().await {
            error!("Could not accept connection: {:?}", msg);
        }

        // Check for end of test in unit tests.
        if end() {
            return Ok(());
        }
    }
}

/// Private helper to perform initialization.
///
/// # Arguments
///
/// * `args` - The command line args.
///
/// # Returns
///
/// * (Config, TcpListener) - The configuration info and the TCP listener.
///
/// ```
#[doc(hidden)]
async fn init(args: impl IntoIterator<Item = String>) -> (Config, TcpListener) {
    // Get the arg iterator and program name from arg 0.
    let mut args = args.into_iter();
    let usage = format!(
        "Usage: {} [--config <file>]",
        args.next().unwrap_or_default().as_str()
    );
    let usage = usage.as_str();
    let mut config_file = None;

    // Parse command line args and see if there is a config file.
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "--config" => {
                config_file = args.next().or_else(|| err_exit("Argument expected", usage))
            }
            "-h" | "--help" => err_exit("", usage),
            _ => err_exit(&format!("Unknown option {arg}"), usage),
        }
    }

    // Initialize the config options.
    let config = match Config::new(config_file.as_deref()) {
        Ok(conf) => conf,
        Err(msg) => err_exit(&msg.to_string(), ""),
    };

    // Initialize logging
    if let Err(msg) = init_logger(config.log_level()) {
        err_exit(&msg.to_string(), "");
    }

    // Verify the SSRF token env variable is set
    if let Err(err) = get_token(&config) {
        let msg = format!(
            "Could not read SSRF token variable(s) {:?}: {err}",
            config.ssrf_env_variables()
        );
        error!("{msg}");
        err_exit(&msg, "");
    }

    // Bind the listener to the specified port
    let addr: SocketAddr = ([127, 0, 0, 1], config.http_port()).into();
    let listener: TcpListener = match TcpListener::bind(addr).await {
        Ok(x) => x,
        Err(err) => {
            let msg = format!("Could not bind to {addr}: {}", err);
            error!("{msg}");
            err_exit(&msg, "");
        }
    };

    (config, listener)
}

/// Private helper print error messages and exit the process with an error.
///
/// # Arguments
///
/// * `msg` - An error message to print (or the empty string if none is to be printed).
/// * `usage` - A usage message to print (or the empty string if none is to be printed).
#[doc(hidden)]
fn err_exit(msg: &str, usage: &str) -> ! {
    if !msg.is_empty() {
        eprintln!("{msg}");
    }
    if !usage.is_empty() {
        eprintln!("{usage}");
    }
    std::process::exit(1);
}
