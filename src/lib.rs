use jwt_simple::prelude::*;
use log;
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

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

static SERVER_PRIVATE_KEY: &str = r#"
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAvYnVJRHILgFKsv5z7ACWaGCQMH5ArbOgFWQBczA9OL43jmaE
sXA+Ju81lcWDi0Y8M1TzIF7HygLSl5z556TSU1JzSxiLefm+LZv5lfT6RMMed+R5
MstDYt0nePE3wxjDNxeWrCFLCZwr6h75KOkBIH6/TbxL0NX+zSy/iSkLCWOmiUSe
DNBX8cLf/P0s0p2yyMrTBvkrb76CMuIyaH15PCGQI6/rNOcnhdxrK5U0jRWncU/s
oZE2YAo1C0zcakFqsuwhqwGbMEqDlQP91biFwBwivmBuyrr4EsWy7qsHa0iDwHuH
WC+/V5FBKR5rhLNzfke2AuTFKaPSF/IUr4GSVwIDAQABAoIBAC3FJRWIj8CcSz+i
NrgdBDU8bFVph5DquZOwzLDWS1JyjNP0acK3iiq4xUXfpn5xfYQf1X5RpQlhWR2H
qMmJgcjhNjpCORxBdO1qpwDRYcZNIARvxdzAPQuYwDlydrbEOhAJwDbc61PsxKYK
yLxaWA1SzjulZuGNa7R8Q9yJbsLbRRg8+dL2npV1Niq2OOxVSUnQH+QbjXRLgsvg
4htwLvthfaEoTeH+7a/M+g+LatjA7Z1qBkXa+xJJPJSz03mPIgCKXHgPV1xigTlG
KvSg69HhEcT8urWkNFRz+PvYp39/l5IfaK4tluFtmjAZw12Id0/LW8p23R6GcqjL
MPaEFZECgYEA5XKbZWTJdUOJVh+MPeLDk7B78Lbv43baL224/ns/kxX3FMKNYZdD
Qo86xXWd/cMOarNzYqT1KqBmT3O+pqfxjnLpibIl3uV3Dnpk0CPXvxRVq3APS37N
v+0dRMNTMetlrZh8ZPpvvhc47TJ5mJTmIPM2v9l8nXwF+PZAckfw9ZUCgYEA03jp
kW5Fjuuhv/VgDTWRHAk93yu20svf+HQoO4YyT23RTdFMvWf83favdro+m7EWsgs4
dKLxPuBXypRICThzdFdcven6xTGHb93XsYQBUJLqJ+GbU1VC876lEyqjIJXusT9W
uuEgXSV8Nl3IQgMN2cUHpqTRiBi1SLmvZ/MU1TsCgYBHLuMe9cG6a5Vz7p2npW5f
p2UMLPUHcJwIEtZNvRbgHvRksGcEW9U2FRF6qR6214jleX7Wn66f5ttW0uXW9ktu
kh/55Bbzq+TfzQDxwezxDvH1GfLkzRYv8PQfnSl2Vz1YOfJ9sWRxaOr0S7CFscwj
dNELfAG5Kf0AXAVqbv9GcQKBgQCGG4K7uJuiBCpCisCL//FzPyUelyFM0v/JFxjA
jtzu5Cy81cN9xillNeCWQYwcvhQvetAln4OwJSNnk9uPBV6qZBCrW2utjDhgp+X2
bElNKK4X9onDMinQW5Fh80MaEhsaCpncz5HvoCsCazzpJ/irpriwZIuAbHLimOb0
3AHVKwKBgFAnw70isjZ9/h1uqLTjCCCA7ASIKQjEVcGXY3bsvVuaDxv+NsZFhpwF
5MgXTEVoiNprj+gXMPC2B0XFmmUdqnDnPM9eyH+SygBfXAnXNoluSDEPrHusEXXI
CuYS3Qoj8BjLxOTqOO+JTtCWUHngnzIlTKtX1znD5qheOZIxAtrC
-----END RSA PRIVATE KEY-----
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

    let key_pair = RS256KeyPair::from_pem(SERVER_PRIVATE_KEY).unwrap();

    key_pair.sign(claims).unwrap()
}
