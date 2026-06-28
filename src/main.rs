use std::collections::HashMap;
use std::env;
use std::sync::Arc;

use axum::{
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::Response,
    routing::any,
    Router,
};
use bytes::Bytes;
use futures_util::{ StreamExt};
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
use tokio_stream::wrappers::ReceiverStream;
use tracing::info;

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
    /// External path prefix this proxy is mounted under, as seen by the
    /// browser (e.g. "/dashboard"). Empty by default, which preserves the
    /// old behavior for deployments that sit at the root of their host.
    ///
    /// Why this is needed: when an Ingress strips this prefix via
    /// `rewrite-target` before forwarding to this proxy, `parts.uri`
    /// inside this app never contains it — the proxy only ever sees the
    /// upstream-relative path. Any path this proxy later hands back to
    /// the browser to navigate to (intended_path, the post-auth redirect
    /// Location) must have the prefix re-attached, or the browser is sent
    /// to a path the public Ingress has no route for — which, for an
    /// auth flow specifically, manifests as a redirect loop back to login
    /// instead of landing on the originally requested page.
    public_path_prefix: String,
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

        // Normalize to "" or "/prefix" (no trailing slash) so every call
        // site can just do `format!("{}{}", prefix, path)` without having
        // to separately worry about double slashes or a missing leading
        // slash depending on how the operator wrote the env var.
        let raw_prefix = env::var("PUBLIC_PATH_PREFIX")
            .unwrap_or_default()
            .trim()
            .trim_end_matches('/')
            .to_string();
        let public_path_prefix = if raw_prefix.is_empty() {
            String::new()
        } else if raw_prefix.starts_with('/') {
            raw_prefix
        } else {
            format!("/{raw_prefix}")
        };

        Config {
            jwt_secret:     env::var("JWT_SECRET_KEY").expect("JWT_SECRET_KEY must be set"),
            upstream_url:   env::var("UPSTREAM_URL").expect("UPSTREAM_URL must be set"),
            iam_login_url:  env::var("IAM_LOGIN_URL").expect("IAM_LOGIN_URL must be set"),
            secure_cookies: !debug,
            excluded_paths,
            upstream_tls_skip_verify,
            public_path_prefix,
        }
    }

    fn is_excluded(&self, path: &str) -> bool {
        self.excluded_paths
            .iter()
            .any(|prefix| path.starts_with(prefix.as_str()))
    }

    /// Re-attach the external prefix to a proxy-internal path before
    /// handing it back to the browser. No-op (returns the path unchanged)
    /// when no prefix is configured, so existing root-mounted deployments
    /// are completely unaffected.
    fn to_public_path(&self, internal_path: &str) -> String {
        if self.public_path_prefix.is_empty()
            || internal_path.starts_with(&self.public_path_prefix) {
            return internal_path.to_string();
        }
        format!("{}{}", self.public_path_prefix, internal_path)
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
                .enable_http1()
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
                .enable_http1()
                .build();
            Client::builder(TokioExecutor::new()).build(https)
        };

        Self { config, client_verified: verified, client_unverified: unverified }
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

    let cookie_header = headers.get("cookie").and_then(|v| v.to_str().ok()).map(String::from);
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
    // `original_url` is `path_and_query` as THIS proxy received it — i.e.
    // already stripped of any external prefix by an upstream Ingress
    // rewrite. Re-attach that prefix here so that when IAM later redirects
    // the browser back to this value, it lands on a path the public
    // Ingress can actually route, instead of looping back through the
    // proxy's own internal-relative path again.
    let public_intended_path = config.to_public_path(original_url);
    builder = builder.header(
        "Set-Cookie",
        build_cookie("intended_path", &public_intended_path, 600, false, config.secure_cookies),
    );
    builder.body(Body::empty()).unwrap()
}

// ─── Hop-by-hop headers ───────────────────────────────────────────────────────
static HOP_BY_HOP_REQ: &[&str] = &[
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
];

// transfer-encoding intentionally NOT stripped from responses
static HOP_BY_HOP_RESP: &[&str] = &[
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers",
];

fn strip_hop_by_hop_request(headers: &mut HeaderMap) {
    for name in HOP_BY_HOP_REQ { headers.remove(*name); }
}

fn strip_hop_by_hop_response(headers: &mut HeaderMap) {
    for name in HOP_BY_HOP_RESP { headers.remove(*name); }
}

fn bad_gateway() -> Response {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(Body::from("Bad Gateway"))
        .unwrap()
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

// ─── Route: handle-auth ───────────────────────────────────────────────────────
async fn handle_auth(
    State(state): State<AppState>,
    axum::extract::Path((access_token, refresh_token)): axum::extract::Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if !validate_jwt(&access_token, &state.config.jwt_secret) {
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::json!({ "error": "Invalid or expired token" }).to_string()))
            .unwrap();
    }

    // `intended_path` was stored (in redirect_to_iam) as a PUBLIC path —
    // i.e. already including this proxy's external prefix, if any — so it
    // can be used directly as the redirect Location without modification.
    // The "/" fallback is likewise a public, root-of-host path and needs
    // no prefix attached either.
    let intended_path = get_cookie(&headers, "intended_path")
    .unwrap_or_else(|| state.config.to_public_path("/"));

    Response::builder()
        .status(StatusCode::FOUND)
        .header("Location", intended_path)
        .header("Set-Cookie", build_cookie("access_token",  &access_token,  86400,  true, state.config.secure_cookies))
        .header("Set-Cookie", build_cookie("refresh_token", &refresh_token, 604800, true, state.config.secure_cookies))
        .header("Set-Cookie", clear_cookie("intended_path"))
        .body(Body::empty())
        .unwrap()
}

// ─── Route: proxy ─────────────────────────────────────────────────────────────
async fn proxy_request(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    req: Request,
) -> Response {
    let (parts, body) = req.into_parts();

    let path = parts.uri.path().to_string();
    let path_and_query = parts.uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| path.clone());


    // ── Auth check ────────────────────────────────────────────────────────────
    if let Err(redirect) = auth_gate(&path, &path_and_query, &parts.headers, &state.config) {
        return redirect;
    }

    info!("Proxying {} {}", parts.method, path_and_query);

    let upstream_path = if !state.config.public_path_prefix.is_empty() {
        path_and_query
            .strip_prefix(&state.config.public_path_prefix)
            .unwrap_or(&path_and_query)
    } else {
        &path_and_query
    };

    let target_uri: hyper::Uri = match format!(
        "{}{}",
        state.config.upstream_url.trim_end_matches('/'),
        upstream_path
    ).parse() {
        Ok(u) => u,
        Err(e) => { tracing::warn!("Bad URI: {e}"); return bad_gateway(); }
    };

    let body_bytes = match body.collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => { tracing::warn!("Body read error: {e}"); return bad_gateway(); }
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
        let host_val = match target_uri.port() {
            Some(p) => format!("{}:{}", host, p),
            None    => host.to_string(),
        };
        if let Ok(val) = HeaderValue::from_str(&host_val) {
            upstream_headers.insert("host", val);
        }
    }

    let mut upstream_req = hyper::Request::builder().method(parts.method).uri(target_uri);
    *upstream_req.headers_mut().unwrap() = upstream_headers;

    let upstream_req = match upstream_req.body(Full::new(body_bytes)) {
        Ok(r) => r,
        Err(e) => { tracing::warn!("Request build error: {e}"); return bad_gateway(); }
    };

    let upstream_resp = match state.client().request(upstream_req).await {
        Ok(r) => r,
        Err(e) => { tracing::warn!("Upstream error: {e}"); return bad_gateway(); }
    };

    tracing::info!(
        status         = %upstream_resp.status(),
        content_type   = ?upstream_resp.headers().get("content-type"),
        transfer_enc   = ?upstream_resp.headers().get("transfer-encoding"),
        content_length = ?upstream_resp.headers().get("content-length"),
        "upstream response"
    );

    let (mut resp_parts, resp_body) = upstream_resp.into_parts();
    strip_hop_by_hop_response(&mut resp_parts.headers);
    resp_parts.headers.insert("x-accel-buffering", HeaderValue::from_static("no"));

    // ── Stream via channel (capacity 1 = no buffering) ────────────────────────
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(1);
    let path_for_log = path_and_query.clone();
    let is_watch = path_and_query.contains("watch=true");

    tokio::spawn(async move {
        let mut stream = resp_body.into_data_stream();
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(bytes) => {
                    if is_watch {
                        tracing::info!(path = %path_for_log, bytes = bytes.len(), "watch chunk");
                    } else {
                        tracing::debug!(path = %path_for_log, bytes = bytes.len(), "chunk");
                    }
                    if tx.send(Ok(bytes)).await.is_err() {
                        tracing::debug!(path = %path_for_log, "client disconnected");
                        break;
                    }
                }
                Err(e) => {
                    tracing::warn!(path = %path_for_log, "stream error: {e}");
                    let _ = tx.send(Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))).await;
                    break;
                }
            }
        }
        tracing::debug!(path = %path_for_log, "stream ended");
    });

    Response::from_parts(resp_parts, Body::from_stream(ReceiverStream::new(rx)))
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
                .unwrap_or_else(|_| "ginger_auth_proxy=debug".into()),
        )
        .init();

    let config = Config::from_env();

    info!(
        debug               = !config.secure_cookies,
        excluded            = ?config.excluded_paths,
        upstream            = %config.upstream_url,
        tls_skip_verify     = config.upstream_tls_skip_verify,
        public_path_prefix  = %config.public_path_prefix,
        "Starting auth-proxy",
    );

    let state = AppState::new(config.clone());

    let app = Router::new()
        .nest(&config.public_path_prefix, Router::new()
            .route("/handle-auth/logout", any(handle_logout))
            .route("/handle-auth/:access_token/:refresh_token", any(handle_auth))
        )
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