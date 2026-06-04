use std::collections::HashMap;
use std::env;
use std::net::IpAddr;
use std::sync::Arc;

use axum::{
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
    Router,
};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tracing::info;
use futures_util::StreamExt;

// ─── JWT Claims ───────────────────────────────────────────────────────────────
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    exp: usize,
    #[serde(flatten)]
    extra: HashMap<String, serde_json::Value>,
}

// ─── TLS: no-op verifier ──────────────────────────────────────────────────────
#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ─── App Config ───────────────────────────────────────────────────────────────
#[derive(Clone)]
struct Config {
    jwt_secret: String,
    upstream_url: String,
    iam_login_url: String,
    secure_cookies: bool,
    excluded_paths: Vec<String>,
    upstream_tls_skip_verify: bool,
}

impl Config {
    fn from_env() -> Self {
        let debug = env::var("DEBUG")
            .map(|v| matches!(v.to_lowercase().as_str(), "true" | "1"))
            .unwrap_or(false);

        let upstream_tls_skip_verify = env::var("UPSTREAM_TLS_SKIP_VERIFY")
            .map(|v| matches!(v.to_lowercase().as_str(), "true" | "1"))
            .unwrap_or(false);

        let excluded_paths = env::var("EXCLUDED_PATHS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();

        Config {
            jwt_secret:     env::var("JWT_SECRET_KEY").expect("JWT_SECRET_KEY must be set"),
            upstream_url:   env::var("UPSTREAM_URL").expect("UPSTREAM_URL must be set"),
            iam_login_url:  env::var("IAM_LOGIN_URL").expect("IAM_LOGIN_URL must be set"),
            secure_cookies: !debug,
            excluded_paths,
            upstream_tls_skip_verify,
        }
    }

    fn is_excluded(&self, path: &str) -> bool {
        self.excluded_paths
            .iter()
            .any(|prefix| path.starts_with(prefix.as_str()))
    }
}

// ─── Shared app state ─────────────────────────────────────────────────────────
#[derive(Clone)]
struct AppState {
    config: Config,
    client_verified: Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>,
    client_unverified: Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>,
}

impl AppState {
    fn new(config: Config) -> Self {
        let verified = {
            let https = HttpsConnectorBuilder::new()
                .with_native_roots()
                .expect("failed to load native TLS roots")
                .https_or_http()
                .enable_http1()   // ← http1 only, no enable_http2()
                .build();
            Client::builder(TokioExecutor::new()).build(https)
        };

        let unverified = {
            let tls = ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();
            let https = HttpsConnectorBuilder::new()
                .with_tls_config(tls)
                .https_or_http()
                .enable_http1()   // ← http1 only, no enable_http2()
                .build();
            Client::builder(TokioExecutor::new()).build(https)
        };

        Self {
            config,
            client_verified: verified,
            client_unverified: unverified,
        }
    }

    fn client(&self) -> &Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>> {
        if self.config.upstream_tls_skip_verify {
            &self.client_unverified
        } else {
            &self.client_verified
        }
    }
}

// ─── JWT ──────────────────────────────────────────────────────────────────────
fn validate_jwt(token: &str, secret: &str) -> bool {
    let mut v = Validation::new(Algorithm::HS256);
    v.validate_exp = true;
    decode::<Claims>(token, &DecodingKey::from_secret(secret.as_bytes()), &v).is_ok()
}

// ─── Cookie helpers ───────────────────────────────────────────────────────────
fn build_cookie(name: &str, value: &str, max_age_secs: u64, http_only: bool, secure: bool) -> String {
    let mut s = format!("{}={}; Max-Age={}; SameSite=Lax; Path=/", name, value, max_age_secs);
    if http_only { s.push_str("; HttpOnly"); }
    if secure    { s.push_str("; Secure"); }
    s
}

fn clear_cookie(name: &str) -> String {
    format!("{}=; Max-Age=0; Path=/", name)
}

fn parse_cookies(header: &str) -> HashMap<String, String> {
    header
        .split(';')
        .filter_map(|pair| {
            let mut kv = pair.splitn(2, '=');
            Some((
                kv.next()?.trim().to_string(),
                kv.next().unwrap_or("").trim().to_string(),
            ))
        })
        .collect()
}

fn get_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| parse_cookies(s).remove(name))
}

// ─── Auth gate ────────────────────────────────────────────────────────────────
// Returns Ok(()) if the request is authenticated, Err(redirect) otherwise.
fn auth_gate(
    path: &str,
    original_url: &str,
    headers: &HeaderMap,
    config: &Config,
) -> Result<(), Response> {
    if config.is_excluded(path) {
        info!("Auth skipped (excluded path): {}", path);
        return Ok(());
    }

    let cookie_header = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let cookies = cookie_header.as_deref().map(parse_cookies).unwrap_or_default();

    match cookies.get("access_token") {
        None => {
            info!("No token — redirecting to IAM (intended: {})", original_url);
            Err(redirect_to_iam(original_url, vec![], config))
        }
        Some(token) if !validate_jwt(token, &config.jwt_secret) => {
            info!("Invalid/expired token — redirecting to IAM (intended: {})", original_url);
            Err(redirect_to_iam(
                original_url,
                vec![clear_cookie("access_token"), clear_cookie("refresh_token")],
                config,
            ))
        }
        _ => Ok(()),
    }
}

fn redirect_to_iam(original_url: &str, extra_cookies: Vec<String>, config: &Config) -> Response {
    let mut builder = Response::builder()
        .status(StatusCode::FOUND)
        .header("Location", config.iam_login_url.as_str());

    for cookie in extra_cookies {
        builder = builder.header("Set-Cookie", cookie);
    }

    builder = builder.header(
        "Set-Cookie",
        build_cookie("intended_path", original_url, 600, false, config.secure_cookies),
    );

    builder.body(Body::empty()).unwrap()
}

// ─── Hop-by-hop headers ───────────────────────────────────────────────────────
static HOP_BY_HOP: &[&str] = &[
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding",
];

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    for name in HOP_BY_HOP {
        headers.remove(*name);
    }
}

// ─── Route: logout ────────────────────────────────────────────────────────────
async fn handle_logout() -> Response {
    Response::builder()
        .status(StatusCode::FOUND)
        .header("Location", "/")
        .header("Set-Cookie", clear_cookie("access_token"))
        .header("Set-Cookie", clear_cookie("refresh_token"))
        .header("Set-Cookie", clear_cookie("intended_path"))
        .body(Body::empty())
        .unwrap()
}

// ─── Route: handle-auth/:accessToken/:refreshToken ───────────────────────────
async fn handle_auth(
    State(state): State<AppState>,
    axum::extract::Path((access_token, refresh_token)): axum::extract::Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if !validate_jwt(&access_token, &state.config.jwt_secret) {
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::json!({ "error": "Invalid or expired token" }).to_string(),
            ))
            .unwrap();
    }

    let intended_path = get_cookie(&headers, "intended_path")
        .unwrap_or_else(|| "/".to_string());

    Response::builder()
        .status(StatusCode::FOUND)
        .header("Location", intended_path)
        .header("Set-Cookie", build_cookie("access_token",  &access_token,  86400,  true, state.config.secure_cookies))
        .header("Set-Cookie", build_cookie("refresh_token", &refresh_token, 604800, true, state.config.secure_cookies))
        .header("Set-Cookie", clear_cookie("intended_path"))
        .body(Body::empty())
        .unwrap()
}

static HOP_BY_HOP_REQ: &[&str] = &[
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
];

static HOP_BY_HOP_RESP: &[&str] = &[
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers",
    // transfer-encoding intentionally kept so chunked streaming works
];

fn strip_hop_by_hop_request(headers: &mut HeaderMap) {
    for name in HOP_BY_HOP_REQ {
        headers.remove(*name);
    }
}

fn strip_hop_by_hop_response(headers: &mut HeaderMap) {
    for name in HOP_BY_HOP_RESP {
        headers.remove(*name);
    }
}

// ─── Route: streaming reverse proxy ──────────────────────────────────────────
use axum::extract::ws::{WebSocket, WebSocketUpgrade, Message as AxumMsg};
use tokio_tungstenite::tungstenite::Message as TungMsg;
use futures_util::{SinkExt};

async fn proxy_request(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    ws_upgrade: Option<WebSocketUpgrade>,
    req: Request,
) -> Response {
    let (parts, body) = req.into_parts();

    let path = parts.uri.path().to_string();
    let path_and_query = parts.uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| path.clone());

    if let Err(redirect) = auth_gate(&path, &path_and_query, &parts.headers, &state.config) {
        return redirect;
    }

    // ── WebSocket upgrade ─────────────────────────────────────────────────────
    if let Some(upgrade) = ws_upgrade {
        let upstream_url = format!(
            "{}{}",
            state.config.upstream_url
                .trim_end_matches('/')
                .replace("http://", "ws://")
                .replace("https://", "wss://"),
            path_and_query
        );

        tracing::info!("WebSocket upgrade → {}", upstream_url);

        let headers = parts.headers.clone();  // ← capture headers

        return upgrade.on_upgrade(move |client_ws| async move {
            if let Err(e) = proxy_websocket(client_ws, upstream_url, headers).await {  // ← pass headers
                tracing::warn!("WebSocket proxy error: {e}");
            }
        });
    }

    // ── Regular HTTP proxy ────────────────────────────────────────────────────
    info!("Proxying {} {}", parts.method, path_and_query);

    let path_and_query = if path_and_query.contains("watch=true")
        && !path_and_query.contains("timeoutSeconds")
    {
        format!("{}&timeoutSeconds=300", path_and_query)
    } else {
        path_and_query
    };

    let target_uri = format!(
        "{}{}",
        state.config.upstream_url.trim_end_matches('/'),
        path_and_query
    );

    let target_uri: hyper::Uri = match target_uri.parse() {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!("Failed to parse upstream URI: {e}");
            return bad_gateway();
        }
    };

    let body_bytes = match body.collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            tracing::warn!("Failed to read request body: {e}");
            return bad_gateway();
        }
    };

    let mut upstream_headers = parts.headers.clone();
    strip_hop_by_hop_request(&mut upstream_headers);

    upstream_headers.insert("connection", HeaderValue::from_static("keep-alive"));

    let client_ip = addr.ip();
    let xff = upstream_headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|existing| format!("{}, {}", existing, client_ip))
        .unwrap_or_else(|| client_ip.to_string());
    if let Ok(val) = HeaderValue::from_str(&xff) {
        upstream_headers.insert("x-forwarded-for", val);
    }

    if let Some(host) = target_uri.host() {
        let host_val = if let Some(port) = target_uri.port() {
            format!("{}:{}", host, port)
        } else {
            host.to_string()
        };
        if let Ok(val) = HeaderValue::from_str(&host_val) {
            upstream_headers.insert("host", val);
        }
    }

    let mut upstream_req = hyper::Request::builder()
        .method(parts.method)
        .uri(target_uri);
    *upstream_req.headers_mut().unwrap() = upstream_headers;

    let upstream_req = match upstream_req.body(Full::new(body_bytes)) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("Failed to build upstream request: {e}");
            return bad_gateway();
        }
    };

    let upstream_resp = match state.client().request(upstream_req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("Upstream request failed: {e}");
            return bad_gateway();
        }
    };

    tracing::info!(
        status         = %upstream_resp.status(),
        content_type   = ?upstream_resp.headers().get("content-type"),
        transfer_enc   = ?upstream_resp.headers().get("transfer-encoding"),
        content_length = ?upstream_resp.headers().get("content-length"),
        connection     = ?upstream_resp.headers().get("connection"),
        "upstream response headers"
    );

    let (mut resp_parts, resp_body) = upstream_resp.into_parts();
    strip_hop_by_hop_response(&mut resp_parts.headers);

    resp_parts.headers.insert(
        "x-accel-buffering",
        HeaderValue::from_static("no"),
    );

    let path_for_log = path_and_query.clone();
    let is_watch = path_and_query.contains("watch=true");
    let stream = resp_body.into_data_stream();
    let logged_stream = stream.map(move |chunk| {
        match &chunk {
            Ok(b) => {
                if is_watch {
                    tracing::info!(path = %path_for_log, bytes = b.len(), "watch chunk");
                } else {
                    tracing::debug!(path = %path_for_log, bytes = b.len(), "chunk");
                }
            }
            Err(e) => tracing::warn!(path = %path_for_log, "stream error: {e}"),
        }
        chunk
    });

    let axum_body = Body::from_stream(logged_stream);
    Response::from_parts(resp_parts, axum_body)
}

async fn proxy_websocket(
    client_ws: WebSocket,
    upstream_url: String,
    original_headers: HeaderMap,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {

    // Build upstream request — let tungstenite generate its own WS handshake headers,
    // only forward cookie and authorization from the original request
    let mut handshake = tokio_tungstenite::tungstenite::http::Request::builder()
        .uri(upstream_url.parse::<tokio_tungstenite::tungstenite::http::Uri>()?);

    if let Some(cookie) = original_headers.get("cookie") {
        handshake = handshake.header("cookie", cookie.as_bytes());
    }
    if let Some(auth) = original_headers.get("authorization") {
        handshake = handshake.header("authorization", auth.as_bytes());
    }

    let handshake_req = handshake.body(())?;

    let (upstream_ws, resp) = tokio_tungstenite::connect_async(handshake_req).await?;
    tracing::info!("WebSocket upstream connected status={}", resp.status());

    let (mut client_tx, mut client_rx) = client_ws.split();
    let (mut up_tx, mut up_rx) = upstream_ws.split();

    let c2u = tokio::spawn(async move {
        while let Some(Ok(msg)) = client_rx.next().await {
            let tung = match msg {
                AxumMsg::Text(t)   => TungMsg::Text(t.to_string().into()),
                AxumMsg::Binary(b) => TungMsg::Binary(b.to_vec().into()),
                AxumMsg::Ping(p)   => TungMsg::Ping(p.to_vec().into()),
                AxumMsg::Pong(p)   => TungMsg::Pong(p.to_vec().into()),
                AxumMsg::Close(_)  => {
                    let _ = up_tx.send(TungMsg::Close(None)).await;
                    break;
                }
            };
            if up_tx.send(tung).await.is_err() { break; }
        }
        tracing::debug!("c2u done");
    });

    let u2c = tokio::spawn(async move {
        while let Some(Ok(msg)) = up_rx.next().await {
            let axum_msg = match msg {
                TungMsg::Text(t)   => AxumMsg::Text(t.to_string().into()),
                TungMsg::Binary(b) => AxumMsg::Binary(b.to_vec().into()),
                TungMsg::Ping(_)   => continue,
                TungMsg::Pong(p)   => AxumMsg::Pong(p.to_vec().into()),
                TungMsg::Close(_)  => {
                    let _ = client_tx.send(AxumMsg::Close(None)).await;
                    break;
                }
                _ => continue,
            };
            if client_tx.send(axum_msg).await.is_err() { break; }
        }
        tracing::debug!("u2c done");
    });

    tokio::join!(c2u, u2c);
    Ok(())
}

fn bad_gateway() -> Response {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(Body::from("Bad Gateway"))
        .unwrap()
}

// ─── Main ─────────────────────────────────────────────────────────────────────
#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install ring crypto provider");

    match dotenvy::dotenv() {
        Ok(path) => eprintln!("Loaded .env from {}", path.display()),
        Err(_)   => eprintln!("No .env file — using environment variables"),
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ginger_auth_proxy=info,tower_http=info".into()),
        )
        .init();

    let config = Config::from_env();

    info!(
        debug           = !config.secure_cookies,
        excluded        = ?config.excluded_paths,
        upstream        = %config.upstream_url,
        tls_skip_verify = config.upstream_tls_skip_verify,
        "Starting auth-proxy",
    );

    let state = AppState::new(config);

    let app = Router::new()
        // ── Logout ────────────────────────────────────────────────────────────
        .route("/handle-auth/logout", any(handle_logout))
        // ── Auth callback ─────────────────────────────────────────────────────
        .route("/handle-auth/:access_token/:refresh_token", any(handle_auth))
        // ── Everything else → streaming proxy ─────────────────────────────────
        .fallback(any(proxy_request))
        .with_state(state)
        .into_make_service_with_connect_info::<std::net::SocketAddr>();

    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);

    let listener = TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .expect("Failed to bind");

    info!("Listening on 0.0.0.0:{}", port);
    eprintln!("Listening on 0.0.0.0:{}", port);

    axum::serve(listener, app).await.expect("Server error");
}