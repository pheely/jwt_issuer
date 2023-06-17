use jwt_simple::prelude::*;
use log;
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use std::io::Error;

static CTS: &str = "OAUTH2_STATELESS_GRANT";
static TOKEN_NAME: &str = "access_token";
static TOKEN_TYPE: &str = "Bearer";
static REALM: &str = "/internals2s";
static GRANT_TYPE: &str = "client_credentials";

static CLIENT_PUBLIC_KEY: &str = r#"
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4W8R3BGGQtKuNufJskRY
9pNUrIxhfkfVbzmcLm28rmY4YHRqVg5PUpzqfCrMFWk5N5385nbQUeFA8rnhPelX
GTFGcYZdsoK/ZHIWgUn2y2kpy6afCYykDRqMeGotahVNlve+/nG94uvOMfDHb3UY
P3RTsU3LtM0sQmfjmp9TEZMW/m4qEBMatTPpUcSR6GOtWmcJjO1Cb6XJXxmVXyDP
nG6kiJB4m/c2VeG+3aLAXvea341cD1Z8guvse3n4U0NLPwXD+eyKLUT2pX3SOf8X
i/8IsGTbfXAEYRJ0zqrBq/AH04a5b4Z34wT2KjYPlZeQ0iSa6hiqQMb5INaqnoLK
rwIDAQAB
-----END PUBLIC KEY-----
"#;

#[derive(jwt_simple::prelude::Serialize, Deserialize)]
struct CustomClaims {
    cts: String,
    auditTrackingId: String,
    subname: String,
    tokenName: String,
    token_type: String,
    authGrantId: String,
    nbf: u64,
    grant_type: String,
    scope: [String; 1],
    auth_time: u64,
    realm: String,
    exp: u64,
    iat: u64,
    expires_in: u64,
    jti: String,
}

pub struct QualifiedEndpoint {
    pub protocol: String,
    pub host: String,
    pub port: String,
    pub path: String,
}

fn process_client_token(
    client_token: &String,
) -> Result<JWTClaims<NoCustomClaims>, jwt_simple::Error> {
    // retrieve the token metadata
    let metadata = Token::decode_metadata(&client_token).unwrap();

    // these should be part of the header
    log::debug!("algorithm: {}", metadata.algorithm());
    // client token does not have key_id or cty
    // println!("key_id: {}", metadata.key_id().unwrap());
    // println!("content_type: {}", metadata.content_type().unwrap());

    // retrieve claims
    let client_key = RS256PublicKey::from_pem(CLIENT_PUBLIC_KEY).unwrap();

    // use all defaults for now
    let options = VerificationOptions::default();

    // the client token does not have any custom claims
    // if we don't panic up to this point, the validaiton is completed
    let claims = client_key.verify_token(&client_token, Some(options));
    log::debug!("claim verified: {:?}", claims);
    claims
}

pub fn create_access_token(
    client_token: &String,
    scope: &String,
    endpoint: QualifiedEndpoint,
    private_key: &Result<String, Error>
) -> String {
    let client_jwt_claims = match process_client_token(client_token) {
        Ok(jwt_claims) => jwt_claims,
        Err(error) => {
            // print the error messahe and create a dummy for now
            log::error!("error: {}", error.to_string());
            Claims::create(Duration::from_mins(1))
                .with_issuer("whatever")
                .with_audience("whatever")
                .with_subject("whatever")
        }
    };
    let subject = client_jwt_claims.subject.as_ref().unwrap();

    let nbf = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let additional_data = CustomClaims {
        cts: String::from(CTS),
        auditTrackingId: Uuid::new_v4().to_string(),
        subname: String::from(subject),
        tokenName: String::from(TOKEN_NAME),
        token_type: String::from(TOKEN_TYPE),
        authGrantId: String::from("NpHu33d0-vQ7teB4l90q7kj9fHs"),
        nbf,
        grant_type: String::from(GRANT_TYPE),
        scope: [String::from(scope)],
        auth_time: nbf,
        realm: String::from(REALM),
        exp: nbf + 3600,
        iat: nbf,
        expires_in: 3600,
        jti: String::from("_z5gC0h_B0LC0OT_9mC4iRm1XQQ"),
    };

    let claims = Claims::with_custom_claims(additional_data, Duration::from_secs(3600))
        .with_issuer(format!(
            "{}://{}:{}{}",
            endpoint.protocol, endpoint.host, endpoint.port, endpoint.path
        ))
        .with_audience(&subject)
        .with_subject(&subject);

    // The private_key is safe to unwrap when we got here
    let key_string = private_key.as_ref();
    let key_pair = RS256KeyPair::from_pem(key_string.unwrap()).unwrap();

    key_pair.sign(claims).unwrap()
}
