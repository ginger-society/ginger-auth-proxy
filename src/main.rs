use std::collections::HashMap;
use std::env;
use std::net::IpAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct};
use serde::{Deserialize, Serialize};
use tracing::info;
use warp::{Filter, Rejection, Reply};

use warp::ws::WebSocket;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

// ─── JWT Claims ───────────────────────────────────────────────────────────────
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    exp: usize,
    #[serde(flatten)]
    extra: HashMap<String, serde_json::Value>,
}

// ─── TLS: no-op verifier for self-signed / internal certs ────────────────────
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



async fn ws_proxy(
    ws: warp::ws::Ws,
    path: warp::path::FullPath,
    query: Option<String>,
    cookie_header: Option<String>,
    config: Config,
) -> Result<Box<dyn warp::Reply>, Rejection> {  // ← Box<dyn Reply>
    let path_str = path.as_str();
    let path_and_query = match query {
        Some(ref q) if !q.is_empty() => format!("{}?{}", path_str, q),
        _ => path_str.to_string(),
    };

    if let Err(redirect) = auth_gate(path_str, &path_and_query, &cookie_header, &config) {
        return Ok(Box::new(redirect));  // ← boxed
    }

    let upstream = format!(
        "{}{}",
        config.upstream_url
            .trim_end_matches('/')
            .replace("http://", "ws://")
            .replace("https://", "wss://"),
        path_and_query
    );

    tracing::info!("WebSocket proxying to: {}", upstream);

    Ok(Box::new(ws.on_upgrade(move |client_ws| async move {  // ← boxed
        if let Err(e) = proxy_websocket(client_ws, upstream).await {
            tracing::warn!("WebSocket proxy error: {:?}", e);
        }
    })))
}
async fn proxy_websocket(
    client_ws: WebSocket,
    upstream_url: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (upstream_ws, _) = connect_async(&upstream_url).await?;

    let (mut client_tx, mut client_rx) = client_ws.split();
    let (mut upstream_tx, mut upstream_rx) = upstream_ws.split();

    // Use channels so both tasks can signal the other to stop cleanly
    let (close_tx, mut close_rx) = tokio::sync::oneshot::channel::<()>();

    // client → upstream
    let c2u = tokio::spawn(async move {
        while let Some(result) = client_rx.next().await {
            let msg = match result {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!("client_rx error: {e}");
                    break;
                }
            };

            let tung_msg = if msg.is_text() {
                Message::Text(msg.to_str().unwrap_or("").to_string().into())
            } else if msg.is_binary() {
                Message::Binary(msg.as_bytes().to_vec().into())
            } else if msg.is_ping() {
                Message::Ping(msg.as_bytes().to_vec().into())
            } else if msg.is_pong() {
                Message::Pong(msg.as_bytes().to_vec().into())
            } else if msg.is_close() {
                let _ = upstream_tx.send(Message::Close(None)).await;
                break;  // clean exit, not an error
            } else {
                continue;
            };

            if let Err(e) = upstream_tx.send(tung_msg).await {
                tracing::warn!("upstream_tx error: {e}");
                break;
            }
        }
        // Signal the other direction to stop
        let _ = close_tx.send(());
    });

    // upstream → client
    let u2c = tokio::spawn(async move {
        loop {
            tokio::select! {
                // Stop if c2u finished
                _ = &mut close_rx => break,

                msg = upstream_rx.next() => {
                    let msg = match msg {
                        Some(Ok(m)) => m,
                        Some(Err(e)) => {
                            tracing::warn!("upstream_rx error: {e}");
                            break;
                        }
                        None => break, // upstream closed
                    };

                    let warp_msg = match msg {
                        Message::Text(t)   => warp::ws::Message::text(t.to_string()),
                        Message::Binary(b) => warp::ws::Message::binary(b.to_vec()),
                        Message::Ping(p)   => warp::ws::Message::ping(p.to_vec()),
                        Message::Pong(p)   => warp::ws::Message::pong(p.to_vec()),
                        Message::Close(_)  => {
                            let _ = client_tx.send(warp::ws::Message::close()).await;
                            break;
                        }
                        _ => continue,
                    };

                    if let Err(e) = client_tx.send(warp_msg).await {
                        tracing::warn!("client_tx error: {e}");
                        break;
                    }
                }
            }
        }
    });

    // Wait for both to finish — don't cancel either
    let _ = tokio::join!(c2u, u2c);
    Ok(())
}

// ─── App Config ───────────────────────────────────────────────────────────────
#[derive(Clone)]
struct Config {
    jwt_secret: String,
    upstream_url: String,
    iam_login_url: String,
    /// DEBUG=true  -> no Secure cookie flag, verbose logs  (local dev)
    /// DEBUG=false -> Secure cookie flag on                (default / prod)
    secure_cookies: bool,
    /// Path prefixes that bypass the auth gate entirely.
    /// Set via EXCLUDED_PATHS=/health,/metrics,/public
    excluded_paths: Vec<String>,
    /// UPSTREAM_TLS_SKIP_VERIFY=true  -> skip TLS cert verification (self-signed / internal certs)
    /// UPSTREAM_TLS_SKIP_VERIFY=false -> verify TLS cert normally   (default)
    upstream_tls_skip_verify: bool,
}

impl Config {
    fn from_env() -> Self {
        let debug = env::var("DEBUG")
            .map(|v| matches!(v.to_lowercase().as_str(), "true" | "1"))
            .unwrap_or(false);

        let upstream_tls_skip_verify = env::var("UPSTREAM_TLS_SKIP_VERIFY")
            .map(|v| matches!(v.to_lowercase().as_str(), "true" | "1"))
            .unwrap_or(false); // default: verify certs (safe for prod)

        let excluded_paths = env::var("EXCLUDED_PATHS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();

        Config {
            jwt_secret: env::var("JWT_SECRET_KEY").expect("JWT_SECRET_KEY must be set"),
            upstream_url: env::var("UPSTREAM_URL").expect("UPSTREAM_URL must be set"),
            iam_login_url: env::var("IAM_LOGIN_URL").expect("IAM_LOGIN_URL must be set"),
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

// ─── JWT Validator ────────────────────────────────────────────────────────────
fn validate_jwt(token: &str, secret: &str) -> bool {
    let mut v = Validation::new(Algorithm::HS256);
    v.validate_exp = true;
    decode::<Claims>(token, &DecodingKey::from_secret(secret.as_bytes()), &v).is_ok()
}

// ─── Cookie helpers ───────────────────────────────────────────────────────────
fn build_cookie(
    name: &str,
    value: &str,
    max_age_secs: u64,
    http_only: bool,
    secure: bool,
) -> String {
    let mut s = format!(
        "{}={}; Max-Age={}; SameSite=Lax; Path=/",
        name, value, max_age_secs
    );
    if http_only {
        s.push_str("; HttpOnly");
    }
    if secure {
        s.push_str("; Secure");
    }
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

// ─── Route: GET /handle-auth/logout ──────────────────────────────────────────
async fn handle_logout() -> Result<impl Reply, Rejection> {
    Ok(Response::builder()
        .status(StatusCode::FOUND)
        .header("Location", "/")
        .header("Set-Cookie", clear_cookie("access_token"))
        .header("Set-Cookie", clear_cookie("refresh_token"))
        .header("Set-Cookie", clear_cookie("intended_path"))
        .body(Bytes::new())
        .unwrap())
}

// ─── Route: GET /handle-auth/:accessToken/:refreshToken ──────────────────────
async fn handle_auth(
    access_token: String,
    refresh_token: String,
    cookie_header: Option<String>,
    config: Config,
) -> Result<impl Reply, Rejection> {
    if !validate_jwt(&access_token, &config.jwt_secret) {
        return Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("Content-Type", "application/json")
            .body(Bytes::from(
                serde_json::json!({ "error": "Invalid or expired token" }).to_string(),
            ))
            .unwrap());
    }

    let cookies = cookie_header
        .as_deref()
        .map(parse_cookies)
        .unwrap_or_default();
    let intended_path = cookies
        .get("intended_path")
        .cloned()
        .unwrap_or_else(|| "/".to_string());

    Ok(Response::builder()
        .status(StatusCode::FOUND)
        .header("Location", intended_path)
        .header(
            "Set-Cookie",
            build_cookie("access_token", &access_token, 86400, true, config.secure_cookies),
        )
        .header(
            "Set-Cookie",
            build_cookie(
                "refresh_token",
                &refresh_token,
                604800,
                true,
                config.secure_cookies,
            ),
        )
        .header("Set-Cookie", clear_cookie("intended_path"))
        .body(Bytes::new())
        .unwrap())
}

// ─── Auth gate ────────────────────────────────────────────────────────────────
fn auth_gate(
    path: &str,
    original_url: &str,
    cookie_header: &Option<String>,
    config: &Config,
) -> Result<(), Response<Bytes>> {
    if config.is_excluded(path) {
        info!("Auth skipped (excluded path): {}", path);
        return Ok(());
    }

    let cookies = cookie_header
        .as_deref()
        .map(parse_cookies)
        .unwrap_or_default();

    match cookies.get("access_token") {
        None => {
            info!(
                "No token — redirecting to IAM (intended: {})",
                original_url
            );
            Err(Response::builder()
                .status(StatusCode::FOUND)
                .header("Location", config.iam_login_url.as_str())
                .header(
                    "Set-Cookie",
                    build_cookie(
                        "intended_path",
                        original_url,
                        600,
                        false,
                        config.secure_cookies,
                    ),
                )
                .body(Bytes::new())
                .unwrap())
        }
        Some(token) if !validate_jwt(token, &config.jwt_secret) => {
            info!(
                "Invalid/expired token — redirecting to IAM (intended: {})",
                original_url
            );
            Err(Response::builder()
                .status(StatusCode::FOUND)
                .header("Location", config.iam_login_url.as_str())
                .header("Set-Cookie", clear_cookie("access_token"))
                .header("Set-Cookie", clear_cookie("refresh_token"))
                .header(
                    "Set-Cookie",
                    build_cookie(
                        "intended_path",
                        original_url,
                        600,
                        false,
                        config.secure_cookies,
                    ),
                )
                .body(Bytes::new())
                .unwrap())
        }
        _ => Ok(()),
    }
}

// ─── Hop-by-hop headers (RFC 7230 §6.1) ──────────────────────────────────────
static HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
];

fn strip_hop_by_hop(headers: &mut hyper::HeaderMap) {
    for name in HOP_BY_HOP {
        headers.remove(*name);
    }
}

// ─── Build hyper client based on TLS config ───────────────────────────────────
//
// Returns a boxed async function to keep the proxy_request signature clean.
// Two variants:
//   • skip_verify = false (default) — uses native roots, verifies certs normally.
//     Works for any properly signed upstream (HTTP or HTTPS).
//   • skip_verify = true            — installs NoVerifier, accepts self-signed /
//     internal certs (e.g. kubernetes-dashboard's auto-generated cert).
enum ProxyClient {
    Verified(Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>),
    Unverified(Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>),
}

impl ProxyClient {
    fn new(skip_verify: bool) -> Self {
        if skip_verify {
            let tls = ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();

            let https = HttpsConnectorBuilder::new()
                .with_tls_config(tls)
                .https_or_http()
                .enable_http1()
                .enable_http2()
                .build();

            Self::Unverified(Client::builder(TokioExecutor::new()).build(https))
        } else {
            let https = HttpsConnectorBuilder::new()
                .with_native_roots()
                .expect("failed to load native TLS roots")
                .https_or_http()
                .enable_http1()
                .enable_http2()
                .build();

            Self::Verified(Client::builder(TokioExecutor::new()).build(https))
        }
    }

    async fn request(
        &self,
        req: Request<Full<Bytes>>,
    ) -> Result<Response<hyper::body::Incoming>, Box<dyn std::error::Error + Send + Sync>> {
        match self {
            Self::Verified(c) => Ok(c.request(req).await?),
            Self::Unverified(c) => Ok(c.request(req).await?),
        }
    }
}

// ─── Reverse-proxy helper ─────────────────────────────────────────────────────
async fn reverse_proxy(
    client_ip: IpAddr,
    upstream_url: &str,
    tls_skip_verify: bool,
    method: hyper::Method,
    path_and_query: String,
    mut headers: hyper::HeaderMap,
    body: Bytes,
) -> Result<Response<Bytes>, Box<dyn std::error::Error + Send + Sync>> {
    // 1. Build the upstream URI
    let target_uri: hyper::Uri = format!(
        "{}{}",
        upstream_url.trim_end_matches('/'),
        path_and_query
    )
    .parse()?;

    // 2. Strip hop-by-hop from outbound headers
    strip_hop_by_hop(&mut headers);

    // 3. X-Forwarded-For
    let xff = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|existing| format!("{}, {}", existing, client_ip))
        .unwrap_or_else(|| client_ip.to_string());
    headers.insert("x-forwarded-for", xff.parse()?);

    // 4. Assemble the upstream request
    let mut req_builder = Request::builder().method(method).uri(target_uri);
    *req_builder.headers_mut().unwrap() = headers;
    let req = req_builder.body(Full::new(body))?;

    // 5. Send via the appropriate client (verified or skip-verify)
    let client = ProxyClient::new(tls_skip_verify);
    let upstream_resp = client.request(req).await?;

    // 6. Strip hop-by-hop from response, collect body
    let (mut parts, upstream_body) = upstream_resp.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    let collected = upstream_body.collect().await?.to_bytes();

    Ok(Response::from_parts(parts, collected))
}

// ─── Proxy handler (warp endpoint) ───────────────────────────────────────────
async fn proxy_request(
    client_addr: Option<IpAddr>,
    cookie_header: Option<String>,
    config: Config,
    method: warp::http::Method,
    path: warp::path::FullPath,
    query: Option<String>,
    headers: warp::http::HeaderMap,
    body: Bytes,
) -> Result<impl Reply, Rejection> {
    let path_str = path.as_str();
    let path_and_query = match query {
        Some(ref q) if !q.is_empty() => format!("{}?{}", path_str, q),
        _ => path_str.to_string(),
    };

    if let Err(redirect) = auth_gate(path_str, &path_and_query, &cookie_header, &config) {
        return Ok(redirect);
    }

    info!("Proxying {} {}", method, path_and_query);

    let ip = client_addr.unwrap_or(IpAddr::from([127, 0, 0, 1]));

    match reverse_proxy(
        ip,
        &config.upstream_url,
        config.upstream_tls_skip_verify,
        method,
        path_and_query,
        headers,
        body,
    )
    .await
    {
        Ok(response) => Ok(response),
        Err(e) => {
            tracing::warn!("Upstream error: {:?}", e);
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Bytes::from("Bad Gateway"))
                .unwrap())
        }
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────────
#[tokio::main]
async fn main() {
    // Install ring as the process-level rustls crypto provider.
    // Must be called before any TLS operation.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install ring crypto provider");

    match dotenvy::dotenv() {
        Ok(path) => eprintln!("Loaded .env from {}", path.display()),
        Err(_) => eprintln!("No .env file — using environment variables"),
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "auth_proxy=info,warp=warn".into()),
        )
        .init();

    let config = Config::from_env();

    info!(
        debug = !config.secure_cookies,
        excluded = ?config.excluded_paths,
        upstream = %config.upstream_url,
        tls_skip_verify = config.upstream_tls_skip_verify,
        "Starting auth-proxy",
    );

    let with_config = {
        let c = config.clone();
        warp::any().map(move || c.clone())
    };
    let cookie_header = warp::header::optional::<String>("cookie");


    // ── Route: WebSocket proxy ────────────────────────────────────────────────
    let ws_route = warp::get()
        .and(warp::ws())  // ← this filter only matches if Upgrade: websocket is present
        .and(warp::path::full())
        .and(
            warp::query::raw()
                .map(Some)
                .or(warp::any().map(|| None::<String>))
                .unify(),
        )
        .and(cookie_header.clone())
        .and(with_config.clone())
        .and_then(ws_proxy);

    // ── Route: logout ─────────────────────────────────────────────────────────
    let logout_route = warp::get()
        .and(warp::path("handle-auth"))
        .and(warp::path("logout"))
        .and(warp::path::end())
        .and_then(handle_logout);

    // ── Route: handle-auth/:accessToken/:refreshToken ─────────────────────────
    let auth_route = warp::get()
        .and(warp::path("handle-auth"))
        .and(warp::path::param::<String>())
        .and(warp::path::param::<String>())
        .and(warp::path::end())
        .and(cookie_header.clone())
        .and(with_config.clone())
        .and_then(handle_auth);

    // ── Route: everything else -> reverse proxy ───────────────────────────────
    let proxy_route = warp::any()
        .and(warp::addr::remote().map(|addr: Option<std::net::SocketAddr>| {
            addr.map(|a| a.ip())
        }))
        .and(cookie_header.clone())
        .and(with_config.clone())
        .and(warp::method())
        .and(warp::path::full())
        .and(
            warp::query::raw()
                .map(Some)
                .or(warp::any().map(|| None::<String>))
                .unify(),
        )
        .and(warp::header::headers_cloned())
        .and(warp::body::bytes())
        .and_then(proxy_request);

    let routes = logout_route.or(ws_route).or(auth_route).or(proxy_route);

    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);

    info!("Listening on 0.0.0.0:{}", port);
    eprintln!("Listening on 0.0.0.0:{}", port);

    warp::serve(routes).run(([0, 0, 0, 0], port)).await;
}