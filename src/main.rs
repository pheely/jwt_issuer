use actix_web::{post, web, App, HttpRequest, HttpServer, Responder, Result};
use jwt_issuer_lib::create_access_token;
use jwt_issuer_lib::QualifiedEndpoint;
use log;
use serde::{Deserialize, Serialize};
use std::env;
use std::process;
use std::fs;
use std::io::Error;

static REDIRECT_URL: &str = "/sso/";
static AUDIENCE: &str = "/sso/oauth2/realms/root/realms/api/access_token";
static CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

static PROTOCOL: &str = "http";
static HOST: &str = "0.0.0.0";
static PORT: &str = "8080";
static PATH: &str = "/sso/oauth2/api";

static mut PRIVATE_KEY: Result<String,Error> = Ok(String::new());

// The following fields are expected from the request payload
// only `scope` is used for now
// client_assertion is a jwt itself
#[derive(Debug, Deserialize)]
struct ClientPayload {
    grant_type: String,
    redirect_uri: String,
    scope: String,
    client_assertion_type: String,
    client_assertion: String,
}

#[derive(Debug, Serialize)]
struct ResponsePayload {
    access_token: String,
    scope: String,
    token_type: String,
    expires_in: u16,
}

#[post("/sso/oauth2/realms/root/realms/api/access_token")]
async fn access_token(
    client_payload: web::Form<ClientPayload>,
    request: HttpRequest,
) -> Result<impl Responder> {
    log::debug!("client_payload is {:?}", client_payload);
    log::debug!("request headers is {:?}", request.headers());

    // TODO: add logic to verify payload
    // TODO: add logic to verify headers

    let scope = &client_payload.scope;
    let client_token = &client_payload.client_assertion;
    let qualified_endpoint = QualifiedEndpoint {
        protocol: String::from(PROTOCOL),
        host: String::from(HOST),
        port: String::from(PORT),
        path: String::from(PATH),
    };

    let access_token: String;
    unsafe {
        access_token = create_access_token(client_token, scope, qualified_endpoint, &PRIVATE_KEY);
    }

    let response_payload = ResponsePayload {
        access_token,
        scope: String::from(scope),
        token_type: String::from("Bearer"),
        expires_in: 3600,
    };

    Ok(web::Json(response_payload))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    
    log::debug!("Starting up...");

    let pem_file = env::var("PEM_FILE");
    if pem_file.is_err() {
        log::error!("Environment variable PEM_FILE not set.");
        process::exit(1);
    }

    let private_key = fs::read_to_string(pem_file.unwrap());
    if private_key.is_err() {
        log::error!("Failed to load the pem file.");
        process::exit(1);
    }

    log::debug!("Pem file loaded...");

    unsafe {
        PRIVATE_KEY = private_key;
    }

    HttpServer::new(|| App::new().service(access_token))
        .bind((HOST, PORT.parse().unwrap()))?
        .run()
        .await
}
