#![allow(unused)]
use lazy_static::lazy_static;
use redis::Client;
use reqwest::blocking;
use std::fmt::format;

use actix_web::{
    App, HttpRequest, HttpResponse, HttpServer, Responder, error, get, middleware, web,
};
use josekit::{
    JoseError,
    jwk::{Jwk, JwkSet},
    jws::alg::rsassa::RsassaJwsAlgorithm,
    jws::{JwsAlgorithm, JwsHeader, JwsVerifier, RS256},
    jwt::{self, JwtPayload},
};
use serde::Deserialize;
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

lazy_static! {
    static ref PUBLIEC_KEY: Vec<u8> = std::fs::read("./public.json").unwrap();
    static ref PRIVATE_KEY: Vec<u8> = std::fs::read("./private.json").unwrap();
}

#[derive(Debug, Clone)]
pub struct UnverifiedToken {
    algorithm: RsassaJwsAlgorithm,
    key_id: Option<String>,
}

impl UnverifiedToken {
    pub fn new() -> Self {
        UnverifiedToken {
            algorithm: RS256,
            key_id: None,
        }
    }
    pub fn set_key_id(&mut self, value: impl Into<String>) {
        self.key_id = Some(value.into());
    }

    pub fn remove_key_id(&mut self) {
        self.key_id = None;
    }
}

impl JwsVerifier for UnverifiedToken {
    fn algorithm(&self) -> &dyn JwsAlgorithm {
        &self.algorithm
    }

    fn key_id(&self) -> Option<&str> {
        match &self.key_id {
            Some(val) => Some(val.as_ref()),
            None => None,
        }
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), JoseError> {
        Ok(())
    }

    fn box_clone(&self) -> Box<dyn JwsVerifier> {
        Box::new(self.clone())
    }
}

pub fn compile_entityid(
    iss: &str,
    sub: &str,
    metadata: Option<Value>,
) -> Result<String, JoseError> {
    let mut header = JwsHeader::new();
    header.set_token_type("JWT");

    let mut payload = JwtPayload::new();
    payload.set_issuer(iss);
    payload.set_subject(sub);
    payload.set_issued_at(&SystemTime::now());

    // Set expiry after 24 horus
    let exp = SystemTime::now() + Duration::from_secs(86400);
    payload.set_expires_at(&exp);

    // TODO: This should become a function in futrue
    // Let us create the JWKS
    let mut keymap = Map::new();
    let public_keydata = &*PUBLIEC_KEY.clone();
    let publickey = Jwk::from_bytes(public_keydata).unwrap();
    let mut keys: Vec<Value> = Vec::new();
    let map: Map<String, Value> = publickey.as_ref().clone();
    keys.push(json!(map));
    // Now outer map
    keymap.insert("keys".to_string(), json!(keys));
    let _ = payload.set_claim("jwks", Some(json!(keymap)));
    // End of JSON manipulation

    // Set the metadata
    let _ = payload.set_claim("metadta", metadata);

    // Signing JWT
    let keydata = &*PRIVATE_KEY.clone();
    let key = Jwk::from_bytes(keydata).unwrap();

    let signer = RS256.signer_from_jwk(&key)?;
    let jwt = jwt::encode_with_signer(&payload, &header, &signer)?;
    Ok(jwt)
}

/// https://openid.net/specs/openid-federation-1_0.html#name-fetch-subordinate-statement-
/// This will try to fetch a given subordinate's statement from the TA/I
#[get("/fetch")]
pub async fn fetch_subordinates(
    req: HttpRequest,
    redis: web::Data<redis::Client>,
) -> actix_web::Result<impl Responder> {
    let params = match web::Query::<HashMap<String, String>>::from_query(req.query_string()) {
        Ok(data) => data,
        Err(_) => return Err(error::ErrorBadRequest("Missing params")),
    };
    let sub = match params.get("sub") {
        Some(data) => data,
        None => return Err(error::ErrorInternalServerError("Missing sub parameter")),
    };

    // After we have the query
    let mut conn = redis
        .get_connection_manager()
        .await
        .map_err(error::ErrorInternalServerError)?;

    let res = redis::Cmd::hget("inmor:subordinates", sub)
        .query_async::<String>(&mut conn)
        .await
        .map_err(error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok()
        .content_type("application/entity-statement+jwt")
        .body(res))
}

/// FIXME: as an example.
/// This function will add a new sub-ordinate entity to
/// a Trust Anchor or intermediate.
pub fn add_subordinate(entity_id: &str) {
    let url = format!("{}/.well-known/openid-federation", entity_id);
    let resp = blocking::get(url).unwrap();

    if resp.status().is_success() {
        // TODO: Check the value of the content-type in respone

        // Means we have some result back
        let data = resp.text().unwrap();
        let verifier = UnverifiedToken::new();
        let (payload, header) = jwt::decode_with_verifier(&data, &verifier).unwrap();
        println!("{}", header);
    }
}
