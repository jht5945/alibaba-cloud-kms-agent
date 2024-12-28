use bytes::Bytes;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{body::Incoming as IncomingBody, Method, Request, Response};
use hyper_util::rt::TokioIo;
use log::error;
use tokio::net::TcpListener;
use tokio::time::timeout;

use crate::cache_manager::CacheManager;
use crate::config::Config;
use crate::constants::MAX_BUF_BYTES;
use crate::error::HttpError;
use crate::parse::GSVQuery;
use crate::utils::{get_token, time_out};
use std::sync::Arc;

/// Handle incoming HTTP requests.
#[derive(Debug, Clone)]
pub struct Server {
    listener: Arc<TcpListener>,
    cache_mgr: Arc<CacheManager>,
    ssrf_token: Arc<String>,
    ssrf_headers: Arc<Vec<String>>,
    path_prefix: Arc<String>,
    max_conn: usize,
}

/// Handle incoming HTTP requests.
/// Implements the HTTP handler. Each incoming request is handled in its own thread.
impl Server {
    /// Create a server instance.
    pub async fn new(
        listener: TcpListener,
        cfg: &Config,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            listener: Arc::new(listener),
            cache_mgr: Arc::new(CacheManager::new(cfg).await?),
            ssrf_token: Arc::new(get_token(cfg)?),
            ssrf_headers: Arc::new(cfg.ssrf_headers()),
            path_prefix: Arc::new(cfg.path_prefix()),
            max_conn: cfg.max_conn(),
        })
    }

    /// Accept the next request on the listener and process it in a separate thread.
    pub async fn serve_request(&self) -> Result<(), Box<dyn std::error::Error>> {
        let (stream, _) = self.listener.accept().await?;
        stream.set_ttl(1)?; // Prohibit network hops
        let io = TokioIo::new(stream);
        let svr_clone = self.clone();
        let rq_cnt = Arc::strong_count(&self.cache_mgr); // concurrent request count
        tokio::task::spawn(async move {
            let svc_fn = service_fn(|req: Request<IncomingBody>| async {
                svr_clone.complete_req(req, rq_cnt).await
            });
            let mut http = http1::Builder::new();
            let http = http.max_buf_size(MAX_BUF_BYTES);
            if let Err(err) = timeout(time_out(), http.serve_connection(io, svc_fn)).await {
                error!("Failed to serve connection: {:?}", err);
            };
        });

        Ok(())
    }

    /// Private helper to process the incoming request body and format a response.
    #[doc(hidden)]
    async fn complete_req(
        &self,
        req: Request<IncomingBody>,
        count: usize,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        let result = self.get_result(&req, count).await;

        // Format the response.
        match result {
            Ok(rsp_body) => Ok(Response::builder()
                .body(Full::new(Bytes::from(rsp_body)))
                .unwrap()),
            Err(e) => Ok(Response::builder()
                .status(e.0)
                .body(Full::new(Bytes::from(e.1)))
                .unwrap()),
        }
    }

    /// Parse an incoming request and provide the response data.
    #[doc(hidden)]
    async fn get_result(
        &self,
        req: &Request<IncomingBody>,
        count: usize,
    ) -> Result<String, HttpError> {
        self.validate_max_conn(req, count)?; // Verify connection limits are not exceeded
        self.validate_token(req)?; // Check for a valid SSRF token
        self.validate_method(req)?; // Allow only GET requests

        match req.uri().path() {
            "/ping" => Ok("healthy".into()), // Standard health check

            // Lambda extension style query
            "/secretsmanager/get" => {
                let qry = GSVQuery::try_from_query(&req.uri().to_string())?;
                Ok(self
                    .cache_mgr
                    .fetch(
                        &qry.secret_id,
                        qry.version_id.as_deref(),
                        qry.version_stage.as_deref(),
                    )
                    .await?)
            }

            // Path style request
            path if path.starts_with(self.path_prefix.as_str()) => {
                let qry = GSVQuery::try_from_path_query(&req.uri().to_string(), &self.path_prefix)?;
                Ok(self
                    .cache_mgr
                    .fetch(
                        &qry.secret_id,
                        qry.version_id.as_deref(),
                        qry.version_stage.as_deref(),
                    )
                    .await?)
            }
            _ => Err(HttpError(404, "Not found".into())),
        }
    }

    /// Verify the incomming request does not exceed the maximum connection limit.
    #[doc(hidden)]
    fn validate_max_conn(
        &self,
        req: &Request<IncomingBody>,
        count: usize,
    ) -> Result<(), HttpError> {
        // Add one to account for the extra server reference in main, allow 2 extra health check conns.
        let limit = if req.uri().path() == "/ping" {
            self.max_conn + 3
        } else {
            self.max_conn + 1
        };
        if count <= limit {
            return Ok(());
        }

        Err(HttpError(429, "Connection limit exceeded".into()))
    }

    /// Verify the request has the correct SSRF token and no forwarding header is set.
    #[doc(hidden)]
    fn validate_token(&self, req: &Request<IncomingBody>) -> Result<(), HttpError> {
        if req.uri().path() == "/ping" {
            return Ok(());
        }

        // Prohibit forwarding.
        let headers = req.headers();
        if headers.contains_key("X-Forwarded-For") {
            error!("Rejecting request with X-Forwarded-For header");
            return Err(HttpError(400, "Forwarded".into()));
        }

        // Iterate through the headers looking for our token
        for header in self.ssrf_headers.iter() {
            if headers.contains_key(header) && headers[header] == self.ssrf_token.as_str() {
                return Ok(());
            }
        }

        error!("Rejecting request with incorrect SSRF token");
        Err(HttpError(403, "Bad Token".into()))
    }

    /// Verify the request is using the GET HTTP verb.
    #[doc(hidden)]
    fn validate_method(&self, req: &Request<IncomingBody>) -> Result<(), HttpError> {
        if *req.method() == Method::GET {
            return Ok(());
        }

        Err(HttpError(405, "Not allowed".into()))
    }
}
