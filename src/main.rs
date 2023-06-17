use actix_web::{post, web, App, HttpRequest, HttpServer, Responder, Result};
use jwt_issuer_lib::create_access_token;
use jwt_issuer_lib::QualifiedEndpoint;
use log;
use serde::{Deserialize, Serialize};

static REDIRECT_URL: &str = "/sso/";
static AUDIENCE: &str = "/sso/oauth2/realms/root/realms/api/access_token";
static CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

static PROTOCOL: &str = "http";
static HOST: &str = "localhost";
static PORT: &str = "8080";
static PATH: &str = "/sso/oauth2/api";

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

    let access_token = create_access_token(client_token, scope, qualified_endpoint);

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

    HttpServer::new(|| App::new().service(access_token))
        .bind((HOST, PORT.parse().unwrap()))?
        .run()
        .await
}
