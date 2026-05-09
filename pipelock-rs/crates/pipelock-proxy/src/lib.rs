//! HTTP forward proxy with request scanning.
//!
//! MVP scope:
//! - Plain HTTP absolute-URI requests (the form a `HTTP_PROXY=` client sends
//!   for `http://...` targets): scan + forward via `reqwest`.
//! - CONNECT for `https://...` is **blocked** for now. Without TLS
//!   interception we can't inspect the tunnel, so allowing CONNECT silently
//!   would violate the "scan everything" invariant. A future phase adds
//!   either policy-driven tunnel allowance or full TLS MITM.

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use pipelock_audit::Auditor;
use pipelock_config::Config;
use pipelock_core::{Action, ScanInput, Verdict};
use pipelock_scanner::Scanner;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

#[derive(thiserror::Error, Debug)]
pub enum ProxyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("addr: {0}")]
    Addr(String),
}

pub struct ProxyState {
    pub scanner: Scanner,
    pub auditor: Auditor,
    pub upstream: reqwest::Client,
}

// Same rationale as `build_state`: `reqwest::Client::builder().build()` only
// fails on TLS backend init issues — a deployment-time programming error, not
// runtime user input — so the lint is silenced.
#[allow(clippy::expect_used)]
pub async fn serve(addr: SocketAddr, cfg: Config, auditor: Auditor) -> Result<(), ProxyError> {
    let state = Arc::new(ProxyState {
        scanner: Scanner::new(cfg),
        auditor,
        upstream: reqwest::Client::builder()
            .pool_max_idle_per_host(0)
            .build()
            .expect("reqwest client builds"),
    });

    let listener = TcpListener::bind(addr).await?;
    tracing::info!(target: "pipelock.proxy", %addr, "listening");
    serve_with_listener(listener, state).await
}

/// Variant exposed for tests that need a known-port listener.
pub async fn serve_with_listener(
    listener: TcpListener,
    state: Arc<ProxyState>,
) -> Result<(), ProxyError> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| {
                let state = Arc::clone(&state);
                async move { Ok::<_, Infallible>(handle(state, req).await) }
            });
            if let Err(e) = http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(io, svc)
                .await
            {
                tracing::debug!(
                    target: "pipelock.proxy",
                    peer = %peer,
                    error = %e,
                    "connection ended",
                );
            }
        });
    }
}

/// Build a `ProxyState` directly — useful for tests that want to share a
/// scanner/auditor across multiple proxy invocations.
//
// `expect()` here unwraps a `reqwest::Client::builder().build()` whose only
// failure mode is a TLS backend init error; that's a deployment-time
// programming error, not runtime user input, so the lint is silenced.
#[allow(clippy::expect_used)]
pub fn build_state(cfg: Config, auditor: Auditor) -> Arc<ProxyState> {
    Arc::new(ProxyState {
        scanner: Scanner::new(cfg),
        auditor,
        upstream: reqwest::Client::builder()
            .pool_max_idle_per_host(0)
            .build()
            .expect("reqwest client builds"),
    })
}

async fn handle(state: Arc<ProxyState>, req: Request<Incoming>) -> Response<Full<Bytes>> {
    let scan_input = build_scan_target(&req);
    let (verdict, host, method, path) = match scan_input {
        Some((url, method, path, host)) => {
            let v = state.scanner.scan(ScanInput::Url(&url));
            (v, Some(host), Some(method), Some(path))
        }
        None => (
            Verdict::block(pipelock_core::Finding::new(
                "proxy",
                "proxy.invalid_request",
                pipelock_core::Severity::Medium,
                "non-proxy request shape (CONNECT or relative URI)",
            )),
            req.uri().host().map(str::to_string),
            Some(req.method().as_str().to_string()),
            Some(req.uri().path().to_string()),
        ),
    };

    state.auditor.emit_request(
        host.as_deref(),
        method.as_deref(),
        path.as_deref(),
        &verdict,
    );

    match verdict.action {
        Action::Allow => match forward(&state, req).await {
            Ok(resp) => resp,
            Err(e) => {
                tracing::warn!(target: "pipelock.proxy", error = %e, "upstream error");
                error_response(StatusCode::BAD_GATEWAY, "upstream error")
            }
        },
        _ => block_response(&verdict),
    }
}

/// Pulls the scannable URL out of an inbound proxy request.
///
/// Supports:
///   - Absolute-URI form: `GET http://host/path HTTP/1.1` (clients with
///     `HTTP_PROXY=` set).
///
/// CONNECT (HTTPS tunneling) returns `None`; the caller treats it as Block.
fn build_scan_target(req: &Request<Incoming>) -> Option<(String, String, String, String)> {
    let method = req.method().clone();
    let uri = req.uri();

    if method == Method::CONNECT {
        return None;
    }

    let scheme = uri.scheme_str()?;
    let host = uri.host()?.to_string();
    let path = uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .to_string();
    let authority = uri.authority()?.as_str().to_string();
    let url = format!("{scheme}://{authority}{path}");
    Some((url, method.as_str().to_string(), path, host))
}

// `expect()` calls below unwrap `http::Response::Builder` accessors whose only
// failure mode is having previously set an invalid header — none of the
// builder steps in this function can produce one — so the lint is silenced.
#[allow(clippy::expect_used)]
async fn forward(
    state: &ProxyState,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, reqwest::Error> {
    let (parts, body) = req.into_parts();
    let url = parts.uri.to_string();
    let method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes())
        .unwrap_or(reqwest::Method::GET);

    let body_bytes = body
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();

    let mut builder = state.upstream.request(method, &url);
    for (name, value) in parts.headers.iter() {
        let nm = name.as_str().to_ascii_lowercase();
        if matches!(
            nm.as_str(),
            "host"
                | "connection"
                | "proxy-connection"
                | "proxy-authorization"
                | "te"
                | "trailers"
                | "transfer-encoding"
                | "upgrade"
                | "keep-alive"
        ) {
            continue;
        }
        if let (Ok(n), Ok(v)) = (
            reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()),
            reqwest::header::HeaderValue::from_bytes(value.as_bytes()),
        ) {
            builder = builder.header(n, v);
        }
    }
    if !body_bytes.is_empty() {
        builder = builder.body(body_bytes.to_vec());
    }

    let upstream_resp = builder.send().await?;
    let status = upstream_resp.status();
    let headers = upstream_resp.headers().clone();
    let bytes = upstream_resp.bytes().await?;

    let mut resp =
        Response::builder().status(StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::OK));
    {
        let resp_headers = resp.headers_mut().expect("builder has headers map");
        for (n, v) in headers.iter() {
            let nm = n.as_str().to_ascii_lowercase();
            if matches!(
                nm.as_str(),
                "connection"
                    | "transfer-encoding"
                    | "keep-alive"
                    | "te"
                    | "trailers"
                    | "upgrade"
                    | "content-length"
            ) {
                continue;
            }
            if let (Ok(name), Ok(val)) = (
                hyper::header::HeaderName::from_bytes(n.as_str().as_bytes()),
                hyper::header::HeaderValue::from_bytes(v.as_bytes()),
            ) {
                resp_headers.append(name, val);
            }
        }
    }
    Ok(resp.body(Full::new(bytes)).expect("response builds"))
}

// Same rationale as `forward`: builder calls use only static, valid header
// names/values, so `.expect("response builds")` cannot fire at runtime.
#[allow(clippy::expect_used)]
fn block_response(verdict: &Verdict) -> Response<Full<Bytes>> {
    let body = serde_json::json!({
        "blocked_by": "pipelock",
        "action": format!("{:?}", verdict.action),
        "findings": verdict.findings,
    });
    let bytes = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("content-type", "application/json")
        .header("x-pipelock-blocked", "1")
        .body(Full::new(Bytes::from(bytes)))
        .expect("response builds")
}

#[allow(clippy::expect_used)]
fn error_response(status: StatusCode, msg: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain")
        .body(Full::new(Bytes::from(msg.as_bytes().to_vec())))
        .expect("response builds")
}
