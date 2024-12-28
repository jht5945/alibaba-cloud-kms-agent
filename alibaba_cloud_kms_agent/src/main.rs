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
#[cfg(not(test))]
fn err_exit(msg: &str, usage: &str) -> ! {
    if !msg.is_empty() {
        eprintln!("{msg}");
    }
    if !usage.is_empty() {
        eprintln!("{usage}");
    }
    std::process::exit(1);
}
#[cfg(test)] // Use panic for testing
fn err_exit(msg: &str, usage: &str) -> ! {
    if !msg.is_empty() {
        panic!("{msg} !!!"); // Suffix message with !!! so we can distinguish it in tests
    }
    if !usage.is_empty() {
        panic!("#{usage}"); // Preceed usage with # so we can distinguish it in tests.
    }
    panic!("Should not get here");
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_secretsmanager as secretsmanager;
    use bytes::Bytes;
    use cache_manager::tests::{
        set_client, timeout_client, DEFAULT_LABEL, DEFAULT_VERSION, FAKE_ARN,
    };
    use http_body_util::{BodyExt, Empty};
    use hyper::header::{HeaderName, HeaderValue};
    use hyper::{client, Request, StatusCode};
    use hyper_util::rt::TokioIo;
    use serde_json::Value;

    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{mpsc, Arc, Mutex};
    use std::time::Duration;
    use std::{fs, thread};

    use tokio::net::TcpStream;
    use tokio::task::JoinSet;
    use tokio::time::timeout;
    #[cfg(unix)]
    use utils::tests::set_test_var; // set_test_var does not work across threads (e.g. run_request)
    use utils::tests::{tmpfile_name, CleanUp};

    fn one_shot() -> bool {
        true // Tell the sever to quit
    }
    fn noop(_addr: &SocketAddr) {}

    // Run a timer for a test that is expected to panic.
    async fn panic_test(args: impl IntoIterator<Item = &str>) {
        let vargs: Vec<String> = args.into_iter().map(String::from).collect();
        let _ = timeout(Duration::from_secs(5), async {
            run(vargs, noop, one_shot).await
        })
        .await
        .expect("Timed out waiting for panic");
        panic!("Did not panic!");
    }

    // Helpers to run the server in the back ground and send it the given request(s).
    async fn run_request(req: &str) -> (StatusCode, Bytes) {
        run_requests_with_verb(vec![("GET", req)])
            .await
            .expect("request failed")
            .pop()
            .unwrap()
    }
    async fn run_requests_with_verb(
        req_vec: Vec<(&str, &str)>,
    ) -> Result<Vec<(StatusCode, Bytes)>, Box<dyn std::error::Error>> {
        run_requests_with_headers(req_vec, vec![("X-Aws-Parameters-Secrets-Token", "xyzzy")]).await
    }
    async fn run_requests_with_headers(
        req_vec: Vec<(&str, &str)>,
        headers: Vec<(&str, &str)>,
    ) -> Result<Vec<(StatusCode, Bytes)>, Box<dyn std::error::Error>> {
        run_requests_with_client(req_vec, headers, None).await
    }
    async fn run_timeout_request(req: &str) -> (StatusCode, Bytes) {
        run_requests_with_client(
            vec![("GET", req)],
            vec![("X-Aws-Parameters-Secrets-Token", "xyzzy")],
            Some(timeout_client()),
        )
        .await
        .expect("request failed")
        .pop()
        .unwrap()
    }
    async fn run_requests_with_client(
        req_vec: Vec<(&str, &str)>,
        headers: Vec<(&str, &str)>,
        opt_client: Option<secretsmanager::Client>,
    ) -> Result<Vec<(StatusCode, Bytes)>, Box<dyn std::error::Error>> {
        // Run server on port 0 which tells the OS to find an open port.
        let args = vec![
            String::from("prog"),
            String::from("--config"),
            String::from("tests/resources/configs/config_file_anyport.toml"),
        ];
        let (tx_addr, rx_addr) = mpsc::channel(); // Open channel for server to report the port
        let (tx_lock, rx_lock) = mpsc::channel(); // Open channel to use as a sync primitive/lock

        let end = move || {
            rx_lock.recv().expect("no shutdown signal") // Wait for shutdown signal
        };
        let rpt = move |addr: &SocketAddr| {
            tx_addr.send(*addr).expect("could not send address");
        };

        // Run the http server in the background and find the port it is using
        let thr = thread::Builder::new().spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                if let Some(client) = opt_client {
                    set_client(client);
                }
                run(args, rpt, end).await.expect("could not run server");
            })
        })?;
        let addr = rx_addr.recv()?;

        // Run the series of requests and build up the responses.
        // Each request is run as an async task so they can overlap time wise.
        let mut join_set = JoinSet::new();
        let send_cnt = req_vec.len();
        let mut idx = 0;
        let responses = Arc::new(Mutex::new(Vec::new()));
        for (meth, query) in req_vec.clone() {
            // Setup the connection to the server
            let stream = TcpStream::connect(addr)
                .await
                .expect("could not setup client stream");
            let io = TokioIo::new(stream);
            let (mut sender, conn) = client::conn::http1::handshake(io)
                .await
                .expect("could not setup client");
            // spawn a task to poll the connection and drive the HTTP state
            tokio::spawn(async move {
                if let Err(e) = conn.await {
                    panic!("Error in connection: {}", e);
                }
            });

            // Format the request
            let mut req = Request::builder()
                .uri(query)
                .method(meth)
                .body(Empty::<Bytes>::new())
                .expect("could not build request");
            for (header, header_val) in headers.clone() {
                req.headers_mut().insert(
                    HeaderName::from_lowercase(header.to_lowercase().as_bytes())?,
                    HeaderValue::from_str(header_val)?,
                );
            }

            // Send the request and add the response to the list.
            let rsp_vec = responses.clone();
            join_set.spawn(async move {
                // Get the response, map IncompleteMessage error to timeout
                let rsp = match sender.send_request(req).await {
                    Ok(x) => x,
                    Err(h_err) if h_err.is_incomplete_message() => {
                        rsp_vec.lock().expect("lock poisoned").push((
                            idx,
                            StatusCode::GATEWAY_TIMEOUT,
                            Bytes::new(),
                        ));
                        return;
                    }
                    _ => panic!("unknown error sending request"),
                };

                // Return the status code and response data
                let status = rsp.status();
                let data = rsp
                    .into_body()
                    .collect()
                    .await
                    .expect("can not read body")
                    .to_bytes();

                rsp_vec
                    .lock()
                    .expect("lock poisoned")
                    .push((idx, status, data));
            });

            // Inject an inter message delay for all but the last request
            idx += 1;
            if idx < send_cnt {
                tx_lock.send(false).expect("could not sync"); // Tell the server to continue for all but the last request.
                tokio::time::sleep(Duration::from_secs(4)).await;
            }
        }

        // Check for errors.
        while let Some(res) = join_set.join_next().await {
            res.expect("task failed");
        }

        // Make sure everything shutdown cleanly.
        tx_lock.send(true).expect("could not sync"); // Tell the server to shut down.
        if let Err(msg) = thr.join() {
            panic!("server failed: {:?}", msg);
        }

        // Return the responses in the original request order and strip out the index.
        let mut rsp_vec = responses.clone().lock().expect("lock poisoned").to_vec();
        rsp_vec.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
        Ok(rsp_vec
            .iter()
            .map(|x| (x.1, x.2.clone()))
            .collect::<Vec<_>>())
    }

    // Private helper to validate the response fields.
    fn validate_response(name: &str, body: Bytes) {
        validate_response_extra(name, DEFAULT_VERSION, vec![DEFAULT_LABEL], body);
    }

    // Private helper to validate the response fields.
    fn validate_response_extra(name: &str, version: &str, labels: Vec<&str>, body: Bytes) {
        let map: serde_json::Map<String, Value> = serde_json::from_slice(&body).unwrap();

        // Validate all the fields.
        let fake_arn = FAKE_ARN.replace("{{name}}", name);
        assert_eq!(map.get("Name").unwrap(), name);
        assert_eq!(map.get("ARN").unwrap(), &fake_arn);
        assert_eq!(map.get("VersionId").unwrap(), version);
        assert_eq!(map.get("SecretString").unwrap(), "hunter2");
        assert_eq!(map.get("CreatedDate").unwrap(), "1569534789.046");
        assert_eq!(
            map.get("VersionStages").unwrap().as_array().unwrap(),
            &labels
        );
    }

    // Private helper to validate an error response.
    fn validate_err(err_code: &str, msg: &str, body: Bytes) {
        let map: serde_json::Map<String, Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(map.get("__type").unwrap(), err_code);
        if !msg.is_empty() && err_code != "InternalFailure" {
            assert_eq!(map.get("message").unwrap(), msg);
        }
    }
}
