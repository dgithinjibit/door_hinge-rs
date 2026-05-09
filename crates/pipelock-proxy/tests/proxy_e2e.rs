#![allow(clippy::unwrap_used, clippy::expect_used)]
//! End-to-end MVP test: real proxy + real upstream + real reqwest client.
//!
//! Boots an upstream HTTP server on a random port, then a `pipelock-proxy`
//! on a random port pointed at no specific upstream. Sends two proxied
//! requests through it (one allowed, one blocked by DLP) and asserts:
//!
//! 1. The allowed request returns the upstream body.
//! 2. The blocked request returns 403 + `x-pipelock-blocked: 1`.
//! 3. The recorder JSONL has one Allow + one Block line, chained.

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use pipelock_audit::Auditor;
use pipelock_config::Config;
use pipelock_core::Action;
use pipelock_recorder::{verify_chain, Recorder};
use std::convert::Infallible;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::net::TcpListener;

async fn spawn_upstream() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(|_req: Request<hyper::body::Incoming>| async {
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(200)
                            .header("content-type", "text/plain")
                            .body(Full::new(Bytes::from_static(b"hello-upstream")))
                            .unwrap(),
                    )
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });
    addr
}

async fn spawn_proxy(cfg: Config, auditor: Auditor) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = pipelock_proxy::build_state(cfg, auditor);
    tokio::spawn(async move {
        let _ = pipelock_proxy::serve_with_listener(listener, Arc::clone(&state)).await;
    });
    addr
}

#[tokio::test]
async fn allow_then_block_with_recorder_chain() {
    let dir = tempdir().unwrap();
    let evidence = dir.path().join("evidence.jsonl");

    let upstream_addr = spawn_upstream().await;
    // Use `localhost` (Host::Domain) instead of `127.0.0.1` so the SSRF
    // literal-IP check doesn't block the test traffic. The proxy still
    // resolves and forwards to the local listener.
    let upstream_url = format!("http://localhost:{}/", upstream_addr.port());

    let recorder = Recorder::open(&evidence).unwrap();
    let auditor = Auditor::new(Some(recorder.clone()));
    let cfg = Config::default();
    let proxy_addr = spawn_proxy(cfg, auditor).await;

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{}", proxy_addr)).unwrap())
        .build()
        .unwrap();

    // 1. Allowed request → upstream body
    let resp = client.get(&upstream_url).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "hello-upstream");

    // 2. Blocked request — AWS access key in query string
    let blocked_url = format!("{}?key=AKIAIOSFODNN7EXAMPLE", upstream_url);
    let resp = client.get(&blocked_url).send().await.unwrap();
    assert_eq!(resp.status(), 403);
    assert_eq!(
        resp.headers()
            .get("x-pipelock-blocked")
            .map(|v| v.to_str().unwrap()),
        Some("1"),
    );

    // 3. Recorder chain: 2 records, allow then block, intact chain.
    // Give the auditor a moment if anything is buffered (it isn't, but be safe).
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let records = recorder.read_all().unwrap();
    assert_eq!(
        records.len(),
        2,
        "expected 2 audit records, got {records:?}"
    );
    assert_eq!(records[0].verdict.action, Action::Allow);
    assert_eq!(records[1].verdict.action, Action::Block);
    assert!(verify_chain(&records).is_none(), "chain must verify");
}
