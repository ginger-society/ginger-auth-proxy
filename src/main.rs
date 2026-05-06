use std::collections::HashMap;
use std::env;
use std::net::IpAddr;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use tracing::info;
use warp::{Filter, Rejection, Reply};

// ─── JWT Claims ───────────────────────────────────────────────────────────────
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    exp: usize,
    #[serde(flatten)]
    extra: HashMap<String, serde_json::Value>,
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
}

impl Config {
    fn from_env() -> Self {
        let debug = env::var("DEBUG")
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

    let cookies = cookie_header.as_deref().map(parse_cookies).unwrap_or_default();
    let intended_path = cookies
        .get("intended_path")
        .cloned()
        .unwrap_or_else(|| "/".to_string());

    Ok(Response::builder()
        .status(StatusCode::FOUND)
        .header("Location", intended_path)
        .header("Set-Cookie", build_cookie("access_token",  &access_token,  86400,  true, config.secure_cookies))
        .header("Set-Cookie", build_cookie("refresh_token", &refresh_token, 604800, true, config.secure_cookies))
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

    let cookies = cookie_header.as_deref().map(parse_cookies).unwrap_or_default();

    match cookies.get("access_token") {
        None => {
            info!("No token — redirecting to IAM (intended: {})", original_url);
            Err(Response::builder()
                .status(StatusCode::FOUND)
                .header("Location", config.iam_login_url.as_str())
                .header("Set-Cookie", build_cookie("intended_path", original_url, 600, false, config.secure_cookies))
                .body(Bytes::new())
                .unwrap())
        }
        Some(token) if !validate_jwt(token, &config.jwt_secret) => {
            info!("Invalid/expired token — redirecting to IAM (intended: {})", original_url);
            Err(Response::builder()
                .status(StatusCode::FOUND)
                .header("Location", config.iam_login_url.as_str())
                .header("Set-Cookie", clear_cookie("access_token"))
                .header("Set-Cookie", clear_cookie("refresh_token"))
                .header("Set-Cookie", build_cookie("intended_path", original_url, 600, false, config.secure_cookies))
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
    "upgrade",
];

fn strip_hop_by_hop(headers: &mut hyper::HeaderMap) {
    for name in HOP_BY_HOP {
        headers.remove(*name);
    }
}

// ─── Reverse-proxy helper ─────────────────────────────────────────────────────
//
// Replaces hyper_reverse_proxy::call(). Steps:
//  1. Rewrite URI to upstream.
//  2. Strip hop-by-hop headers from the outbound request.
//  3. Inject / append X-Forwarded-For.
//  4. Forward via hyper-util Client (connection-pooled, TokioExecutor).
//  5. Strip hop-by-hop from the upstream response.
//  6. Collect the upstream body into Bytes.
//
// Collecting into Bytes is appropriate for an auth proxy that doesn't
// stream large media payloads — and it's the simplest way to satisfy
// warp's Reply bound (bodyt::Body: From<Bytes>).
async fn reverse_proxy(
    client_ip: IpAddr,
    upstream_url: &str,
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

    // 3. X-Forwarded-For: append our client IP to any existing value
    let xff = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|existing| format!("{}, {}", existing, client_ip))
        .unwrap_or_else(|| client_ip.to_string());
    headers.insert("x-forwarded-for", xff.parse()?);

    // 4. Assemble the request.
    //    The body was already buffered into Bytes by warp::body::bytes(),
    //    so Full<Bytes> is the correct wrapper — zero extra allocation.
    //    Full<Bytes>: Body::Data = Bytes, Body::Error = Infallible,
    //    both satisfy Client's bounds.
    let mut req_builder = Request::builder().method(method).uri(target_uri);
    *req_builder.headers_mut().unwrap() = headers;
    let req = req_builder.body(Full::new(body))?;

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build_http();

    let upstream_resp = client.request(req).await?;

    // 5. Strip hop-by-hop from upstream response headers
    let (mut parts, upstream_body) = upstream_resp.into_parts();
    strip_hop_by_hop(&mut parts.headers);

    // 6. Collect the streaming body into Bytes
    let collected = upstream_body.collect().await?.to_bytes();

    Ok(Response::from_parts(parts, collected))
}

// ─── Proxy handler (warp endpoint) ───────────────────────────────────────────
//
// warp decomposes each request into individually extracted values.
// We receive them as flat arguments and re-use them directly — no need
// to reassemble a full hyper::Request at the warp layer.
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

    match reverse_proxy(ip, &config.upstream_url, method, path_and_query, headers, body).await {
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
    match dotenvy::dotenv() {
        Ok(path) => eprintln!("Loaded .env from {}", path.display()),
        Err(_)   => eprintln!("No .env file — using environment variables"),
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
        "Starting auth-proxy",
    );

    let with_config = {
        let c = config.clone();
        warp::any().map(move || c.clone())
    };
    let cookie_header = warp::header::optional::<String>("cookie");

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
    //
    // warp::body::bytes() eagerly buffers the request body. This replaces
    // the old manual Request reassembly from parts and also sidesteps the
    // Request<Incoming>-is-not-Clone problem that blocks warp::ext::get.
    let proxy_route = warp::any()
        .and(warp::addr::remote().map(|addr: Option<std::net::SocketAddr>| {
            addr.map(|a| a.ip())
        }))
        .and(cookie_header.clone())
        .and(with_config.clone())
        .and(warp::method())
        .and(warp::path::full())
        .and(warp::query::raw().map(Some).or(warp::any().map(|| None::<String>)).unify())
        .and(warp::header::headers_cloned())
        .and(warp::body::bytes())
        .and_then(proxy_request);

    let routes = logout_route.or(auth_route).or(proxy_route);

    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);

    info!("Listening on 0.0.0.0:{}", port);
    eprintln!("Listening on 0.0.0.0:{}", port);

    warp::serve(routes).run(([0, 0, 0, 0], port)).await;
}