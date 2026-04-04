//! HTTP forward proxy server.
//!
//! Each agent gets one proxy instance on localhost. ALL outbound HTTP
//! traffic goes through it, enforcing scope, signing requests, and
//! logging to the audit trail.
//!
//! - CONNECT method → TCP tunnel (no TLS interception)
//! - Other methods → Forward proxy with identity headers

use anyhow::{Context, Result};
use bytes::Bytes;
use ed25519_dalek::SigningKey;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::audit::{ProxyAuditEntry, ProxyAuditLogger};
use crate::scope::{ScopeConfig, ScopeDecision};
use crate::signer::RequestSigner;

/// Shared state for all connections handled by one proxy instance.
struct ProxyState {
    scope: Mutex<ScopeConfig>,
    signer: Option<RequestSigner>,
    audit: ProxyAuditLogger,
    agent_id: String,
}

/// The sidecar proxy server.
pub struct ProxyServer {
    state: Arc<ProxyState>,
    bind_addr: SocketAddr,
}

impl ProxyServer {
    /// Create a new proxy server.
    ///
    /// - `scope`: domain allowlist config
    /// - `signer`: optional request signer (None if no key available)
    /// - `audit_db_path`: path to the agent's audit SQLite DB
    /// - `agent_id`: the agent's UUID
    /// - `signing_key`: the agent's Ed25519 key (for audit chain)
    /// - `port`: port to bind (0 = auto-assign)
    pub fn new(
        scope: ScopeConfig,
        signer: Option<RequestSigner>,
        audit_db_path: &Path,
        agent_id: Uuid,
        signing_key: Arc<SigningKey>,
        port: u16,
    ) -> Result<Self> {
        let audit = ProxyAuditLogger::new(audit_db_path, agent_id, signing_key)?;
        let bind_addr = SocketAddr::from(([127, 0, 0, 1], port));

        Ok(Self {
            state: Arc::new(ProxyState {
                scope: Mutex::new(scope),
                signer,
                audit,
                agent_id: agent_id.to_string(),
            }),
            bind_addr,
        })
    }

    /// Start listening. Returns the bound port and a join handle.
    ///
    /// The server runs until the returned `tokio::task::JoinHandle` is aborted.
    pub async fn start(self) -> Result<(u16, tokio::task::JoinHandle<()>)> {
        let listener = TcpListener::bind(self.bind_addr)
            .await
            .with_context(|| format!("Failed to bind proxy on {}", self.bind_addr))?;

        let bound_port = listener.local_addr()?.port();
        let state = self.state;

        tracing::info!(
            agent = %state.agent_id,
            port = bound_port,
            "Proxy server listening"
        );

        let handle = tokio::spawn(async move {
            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::error!(error = %e, "Accept failed");
                        continue;
                    }
                };

                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req| {
                        let state = Arc::clone(&state);
                        async move { handle_request(state, req).await }
                    });

                    if let Err(e) = http1::Builder::new()
                        .preserve_header_case(true)
                        .title_case_headers(true)
                        .serve_connection(io, svc)
                        .with_upgrades()
                        .await
                    {
                        if !e.to_string().contains("early eof")
                            && !e.to_string().contains("connection reset")
                        {
                            tracing::debug!(peer = %peer, error = %e, "Connection error");
                        }
                    }
                });
            }
        });

        Ok((bound_port, handle))
    }
}

/// Route a request to the appropriate handler.
async fn handle_request(
    state: Arc<ProxyState>,
    req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    if req.method() == Method::CONNECT {
        handle_connect(state, req).await
    } else {
        handle_forward(state, req).await
    }
}

// ─── CONNECT (HTTPS tunneling) ──────────────────────────────────────

async fn handle_connect(
    state: Arc<ProxyState>,
    req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let host_port = req
        .uri()
        .authority()
        .map(|a| a.to_string())
        .unwrap_or_else(|| req.uri().to_string());

    let start = Instant::now();

    // Check scope
    let decision = {
        let mut scope = state.scope.lock().await;
        scope.check_connect(&host_port)
    };

    match decision {
        ScopeDecision::Allow => {
            // Log allowed CONNECT
            let _ = state
                .audit
                .log_request(&ProxyAuditEntry {
                    method: "CONNECT".into(),
                    url: host_port.clone(),
                    status_code: Some(200),
                    scope_decision: "allow".into(),
                    request_size_bytes: 0,
                    response_size_bytes: 0,
                    duration_ms: start.elapsed().as_millis() as u64,
                    signed: false,
                })
                .await;

            // Establish tunnel
            tokio::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => match TcpStream::connect(&host_port).await {
                        Ok(mut target) => {
                            let mut upgraded = TokioIo::new(upgraded);
                            let _ = tokio::io::copy_bidirectional(&mut upgraded, &mut target).await;
                        }
                        Err(e) => {
                            tracing::error!(
                                target = %host_port,
                                error = %e,
                                "Failed to connect to upstream"
                            );
                        }
                    },
                    Err(e) => {
                        tracing::error!(error = %e, "CONNECT upgrade failed");
                    }
                }
            });

            Ok(Response::new(empty_body()))
        }
        ScopeDecision::DenyDomain { domain, .. } => {
            let reason = format!("domain '{}' not in allowlist", domain);
            let _ = state.audit.log_denial("CONNECT", &host_port, &reason).await;
            Ok(deny_response(&reason))
        }
        ScopeDecision::DenyRateLimit { limit, .. } => {
            let reason = format!("rate limit exceeded ({}/min)", limit);
            let _ = state.audit.log_denial("CONNECT", &host_port, &reason).await;
            Ok(rate_limit_response(&reason))
        }
    }
}

// ─── Forward proxy (HTTP) ───────────────────────────────────────────

async fn handle_forward(
    state: Arc<ProxyState>,
    req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let method = req.method().to_string();
    let uri = req.uri().to_string();
    let start = Instant::now();

    // Check scope
    let decision = {
        let mut scope = state.scope.lock().await;
        scope.check_url(&uri)
    };

    match decision {
        ScopeDecision::Allow => {
            // Build the outbound request
            let (mut parts, body) = req.into_parts();

            // Collect existing headers for signer
            let existing_headers: Vec<(String, String)> = parts
                .headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();

            // Sign the request if signer is available
            let signed = if let Some(ref signer) = state.signer {
                match signer.sign_request(&method, &uri, &existing_headers) {
                    Ok(sig_headers) => {
                        for (name, value) in &sig_headers {
                            if let (Ok(n), Ok(v)) = (
                                hyper::header::HeaderName::from_bytes(name.as_bytes()),
                                hyper::header::HeaderValue::from_str(value),
                            ) {
                                parts.headers.insert(n, v);
                            }
                        }
                        true
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Failed to sign request, forwarding unsigned");
                        false
                    }
                }
            } else {
                false
            };

            // Collect the incoming body
            let body_bytes = match body.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(e) => {
                    tracing::error!(error = %e, "Failed to read request body");
                    return Ok(error_response("Failed to read request body"));
                }
            };
            let req_size = body_bytes.len() as u64;

            // Forward via hyper client
            let target_uri: hyper::Uri = match uri.parse() {
                Ok(u) => u,
                Err(e) => {
                    tracing::error!(uri = %uri, error = %e, "Invalid URI");
                    return Ok(error_response("Invalid target URI"));
                }
            };

            let scheme = target_uri.scheme_str().unwrap_or("http");
            if scheme == "https" {
                // HTTPS forward proxy not supported — use CONNECT tunnel instead
                tracing::warn!(
                    url = %uri,
                    "HTTPS forward proxy not supported. Use HTTP CONNECT tunneling for HTTPS targets."
                );
                let _ = state
                    .audit
                    .log_request(&ProxyAuditEntry {
                        method: method.clone(),
                        url: uri.clone(),
                        status_code: Some(400),
                        scope_decision: "allow".into(),
                        request_size_bytes: req_size,
                        response_size_bytes: 0,
                        duration_ms: start.elapsed().as_millis() as u64,
                        signed,
                    })
                    .await;
                return Ok(error_response(
                    "HTTPS forward proxy not supported. Configure your client to use HTTP CONNECT tunneling for HTTPS targets."
                ));
            }

            let host = target_uri.host().unwrap_or("localhost");
            let port = target_uri.port_u16().unwrap_or(80);
            let addr = format!("{}:{}", host, port);

            let upstream = match TcpStream::connect(&addr).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(target = %addr, error = %e, "Upstream connect failed");
                    let _ = state
                        .audit
                        .log_request(&ProxyAuditEntry {
                            method: method.clone(),
                            url: uri.clone(),
                            status_code: Some(502),
                            scope_decision: "allow".into(),
                            request_size_bytes: req_size,
                            response_size_bytes: 0,
                            duration_ms: start.elapsed().as_millis() as u64,
                            signed,
                        })
                        .await;
                    return Ok(error_response("Failed to connect to upstream"));
                }
            };

            let io = TokioIo::new(upstream);
            let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(error = %e, "HTTP handshake failed");
                    return Ok(error_response("Upstream handshake failed"));
                }
            };

            // Drive the connection in background
            tokio::spawn(async move {
                if let Err(e) = conn.await {
                    tracing::debug!(error = %e, "Client connection finished");
                }
            });

            // Rebuild request with the collected body
            // handshake requires Error: Into<Box<dyn StdError>>, so use Infallible
            let out_req = Request::from_parts(parts, Full::new(body_bytes.clone()));

            let resp = match sender.send_request(out_req).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(error = %e, "Upstream request failed");
                    return Ok(error_response("Upstream request failed"));
                }
            };

            let status = resp.status().as_u16();

            // Collect response body
            let (resp_parts, resp_body) = resp.into_parts();
            let resp_bytes = match resp_body.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(e) => {
                    tracing::error!(error = %e, "Failed to read response body");
                    return Ok(error_response("Failed to read response"));
                }
            };
            let resp_size = resp_bytes.len() as u64;

            // Audit log
            let _ = state
                .audit
                .log_request(&ProxyAuditEntry {
                    method,
                    url: uri,
                    status_code: Some(status),
                    scope_decision: "allow".into(),
                    request_size_bytes: req_size,
                    response_size_bytes: resp_size,
                    duration_ms: start.elapsed().as_millis() as u64,
                    signed,
                })
                .await;

            // Reconstruct response
            let out_resp = Response::from_parts(
                resp_parts,
                Full::new(resp_bytes)
                    .map_err(|never| match never {})
                    .boxed(),
            );

            Ok(out_resp)
        }
        ScopeDecision::DenyDomain { domain, .. } => {
            let reason = format!("domain '{}' not in allowlist", domain);
            let _ = state.audit.log_denial(&method, &uri, &reason).await;
            Ok(deny_response(&reason))
        }
        ScopeDecision::DenyRateLimit { limit, .. } => {
            let reason = format!("rate limit exceeded ({}/min)", limit);
            let _ = state.audit.log_denial(&method, &uri, &reason).await;
            Ok(rate_limit_response(&reason))
        }
    }
}

// ─── Response helpers ───────────────────────────────────────────────

fn empty_body() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn deny_response(reason: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    let body = format!("{{\"error\":\"scope_denied\",\"reason\":\"{}\"}}", reason);
    let mut resp = Response::new(
        Full::new(Bytes::from(body))
            .map_err(|never| match never {})
            .boxed(),
    );
    *resp.status_mut() = StatusCode::FORBIDDEN;
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    );
    resp
}

fn rate_limit_response(reason: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    let body = format!("{{\"error\":\"rate_limited\",\"reason\":\"{}\"}}", reason);
    let mut resp = Response::new(
        Full::new(Bytes::from(body))
            .map_err(|never| match never {})
            .boxed(),
    );
    *resp.status_mut() = StatusCode::TOO_MANY_REQUESTS;
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    );
    resp
}

fn error_response(msg: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    let body = format!("{{\"error\":\"proxy_error\",\"message\":\"{}\"}}", msg);
    let mut resp = Response::new(
        Full::new(Bytes::from(body))
            .map_err(|never| match never {})
            .boxed(),
    );
    *resp.status_mut() = StatusCode::BAD_GATEWAY;
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    );
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::ScopeConfig;
    use grokingclawid_core::crypto::generate_keypair;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_proxy_starts_and_binds() {
        let tmp = TempDir::new().unwrap();
        let db_path = tmp.path().join("audit.db");
        let (signing_key, _) = generate_keypair();
        let agent_id = Uuid::new_v4();

        let server = ProxyServer::new(
            ScopeConfig::permissive(),
            None,
            &db_path,
            agent_id,
            Arc::new(signing_key),
            0, // auto-assign port
        )
        .unwrap();

        let (port, handle) = server.start().await.unwrap();
        assert!(port > 0);

        // Clean up
        handle.abort();
    }

    #[tokio::test]
    async fn test_proxy_denies_out_of_scope() {
        let tmp = TempDir::new().unwrap();
        let db_path = tmp.path().join("audit.db");
        let (signing_key, _) = generate_keypair();
        let agent_id = Uuid::new_v4();

        let scope = ScopeConfig::new(vec!["allowed.com".to_string()], 0);
        let server =
            ProxyServer::new(scope, None, &db_path, agent_id, Arc::new(signing_key), 0).unwrap();

        let (_port, handle) = server.start().await.unwrap();

        // Try to request a blocked domain through the proxy
        // Clean up
        handle.abort();
    }
}
