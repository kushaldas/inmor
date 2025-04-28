#![allow(unused)]
use lazy_static::lazy_static;
use log::debug;
use redis::Client;
use reqwest::blocking;
use std::fmt::format;

use actix_web::{
    App, HttpRequest, HttpResponse, HttpServer, Responder, error, get, middleware, web,
};
use actix_web_lab::extract::Query;

use base64::Engine;
use josekit::{
    JoseError,
    jwk::{Jwk, JwkSet},
    jws::alg::rsassa::RsassaJwsAlgorithm,
    jws::{ES512, JwsAlgorithm, JwsHeader, JwsVerifier, PS256, RS256},
    jwt::{self, JwtPayload},
    util,
};
use serde::Serialize;
use serde::{Deserialize, de::Error};
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

lazy_static! {
    static ref PUBLIEC_KEY: Vec<u8> = std::fs::read("./public.json").unwrap();
    static ref PRIVATE_KEY: Vec<u8> = std::fs::read("./private.json").unwrap();
}
pub const WELL_KNOWN: &str = ".well-known/openid-federation";

/// FIXME: get all parameters
#[derive(Debug, Deserialize)]
pub struct ResolveParams {
    sub: String,
    #[serde(rename = "trust_anchor")]
    trust_anchors: Vec<String>,
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

/// Get JWK Set from the given payload
pub fn get_jwks_from_payload(payload: &JwtPayload) -> JwkSet {
    let jwks_data = payload.claim("jwks").unwrap();
    let keys = jwks_data.get("keys").unwrap();
    let mut internal_map: Map<String, Value> = Map::new();
    internal_map.insert("keys".to_string(), keys.clone());
    let jwks = JwkSet::from_map(internal_map).unwrap();
    jwks
}

pub fn get_unverified_payload_header(data: &str) -> (JwtPayload, JwsHeader) {
    let mut indexies: Vec<usize> = Vec::new();
    let mut i: usize = 0;
    for d in data.as_bytes().iter() {
        if *d == b'.' {
            indexies.push(i);
        }
        i += 1;
    }

    let input = data.as_bytes();
    //if indexies.len() != 2 {
    //bail!("The compact serialization form of JWS must be three parts separated by colon.");
    //}

    let header = &input[0..indexies[0]];
    let payload = &input[(indexies[0] + 1)..(indexies[1])];
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header)
        .unwrap();
    let header: Map<String, Value> = serde_json::from_slice(&header).unwrap();
    let header = JwsHeader::from_map(header).unwrap();
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .unwrap();
    let map: Map<String, Value> = serde_json::from_slice(&payload).unwrap();
    let payload = JwtPayload::from_map(map).unwrap();
    // End of stupid unverified code
    (payload, header)
}

/// Verify JWT against given JWKS
pub fn verify_jwt_with_jwks(data: &str, keys: Option<JwkSet>) -> (JwtPayload, JwsHeader) {
    // Code to find the header & payload without any verification
    let (payload, header) = get_unverified_payload_header(data); // Now either use the passed one or use self keys
    let jwks = match keys {
        Some(d) => d,
        None => get_jwks_from_payload(&payload),
    };
    // FIXME: veify it exits
    let kid = header.key_id().unwrap();
    // Let us find the key used to sign the JWT
    let key = jwks.get(kid)[0];
    // FIXME: We need different verifiers for different kinds of
    // JWK.
    let boxed_verifier: Box<dyn JwsVerifier> = match header.algorithm().unwrap() {
        "RS256" => Box::new(RS256.verifier_from_jwk(&key).unwrap()),
        "PS256" => Box::new(PS256.verifier_from_jwk(&key).unwrap()),
        // FIXME: This has to be fixed for all different keys
        _ => Box::new(ES512.verifier_from_jwk(&key).unwrap()),
    };
    let verifier = &*boxed_verifier;
    let (payload, header) = jwt::decode_with_verifier(&data, verifier).unwrap();
    (payload, header)
}

/// This function will self veify the JWT and returns
/// the payload and header after verification.
pub fn self_verify_jwt(data: &str) -> (JwtPayload, JwsHeader) {
    let (payload, header) = get_unverified_payload_header(data);
    let jwks = get_jwks_from_payload(&payload);
    let (payload, header) = verify_jwt_with_jwks(data, Some(jwks));
    (payload, header)
}

pub async fn resolve_entity_to_trustanchor(
    sub: &str,
    trust_anchors: Vec<&str>,
    start: bool,
) -> Vec<String> {
    eprintln!("\nReceived {} with trust anchors {:?}", sub, trust_anchors);

    // This will hold the list of trust chain
    let mut result = Vec::new();

    // to stop infinite loop
    let mut visited: HashMap<String, bool> = HashMap::new();
    // First get the entity configuration and self verify
    let original_ec = get_entity_configruation_as_jwt(&sub).await;
    // Add it already visited
    visited.insert(sub.to_string(), true);

    if start == true {
        result.push(original_ec.clone());
    }

    let (opayload, oheader) = self_verify_jwt(&original_ec);
    // Now find the authority_hints
    let authority_hints = opayload.claim("authority_hints").unwrap();
    // Loop over the authority hints
    for ah in authority_hints.as_array().unwrap() {
        // Flag to mark if we found the trust anchor
        let mut ta_flag = false;
        // Get the str from the JSON value
        let ah_entity: &str = ah.as_str().unwrap();
        // If we already visited the authority then continue
        if visited.get(ah_entity).is_some() {
            continue;
        }
        // If this is one of the trust anchor, then we are done
        if trust_anchors.iter().any(|i| *i == ah_entity) {
            // Means we found our trust anchor
            ta_flag = true;
        }
        // Fetch the authority's entity configuration
        let ah_jwt = get_entity_configruation_as_jwt(ah_entity).await;
        // Verify and get the payload
        let (ah_payload, _) = self_verify_jwt(&ah_jwt);
        // Now find the fetch endpoint
        let ah_metadata = ah_payload.claim("metadata").unwrap();
        let fetch_endpoint = ah_metadata
            .get("federation_entity")
            .unwrap()
            .get("federation_fetch_endpoint")
            .unwrap();
        // Fetch the entity statement/ subordinate statement
        let sub_statement =
            fetch_subordinate_statement(fetch_endpoint.as_str().unwrap(), &sub).await;
        // Get the authority's JWKS and then verify the subordinate statement against them.
        let ah_jwks = get_jwks_from_payload(&ah_payload);
        let (subs_payload, _) = verify_jwt_with_jwks(&sub_statement, Some(ah_jwks));
        // FIXME: In future if the above fails, then we should move to the next authority
        if ta_flag == true {
            // Means this is the end of resolving
            result.push(sub_statement);
            result.push(ah_jwt.clone());
            return result;
        } else {
            result.push(sub_statement);
            // Now do a recursive query
            result.extend(
                Box::pin(resolve_entity_to_trustanchor(
                    ah_entity,
                    trust_anchors,
                    false,
                ))
                .await,
            );
            return result;
        }
    }
    return vec![];
}

/// https://openid.net/specs/openid-federation-1_0.html#name-resolve-request
#[get("/resolve")]
pub async fn resolve_entity(
    info: Query<ResolveParams>,
    redis: web::Data<redis::Client>,
) -> actix_web::Result<impl Responder> {
    let ResolveParams { sub, trust_anchors } = info.into_inner();
    let tas: Vec<&str> = trust_anchors.iter().map(|s| s as &str).collect();
    // Now loop over the trust_anchors
    let result = resolve_entity_to_trustanchor(&sub, tas, true).await;
    for res in result.iter() {
        println!("\n{}\n", res);
    }
    Ok("hello")
}

/// Fetches the subordinate statement from authority
pub async fn fetch_subordinate_statement(fetch_url: &str, entity_id: &str) -> String {
    let url = format!("{}?sub={}", fetch_url, entity_id);
    debug!("FETCH {}", url);
    return get_query(&url).await;
}

/// Get the entity configuration for a given entity_id
pub async fn get_entity_configruation_as_jwt(entity_id: &str) -> String {
    let url = format!("{}/{}", entity_id, WELL_KNOWN);
    debug!("EC {}", url);
    return get_query(&url).await;
}

/// To do a GET query
pub async fn get_query(url: &str) -> String {
    reqwest::get(url).await.unwrap().text().await.unwrap()
}

/// FIXME: as an example.
/// This function will add a new sub-ordinate entity to
/// a Trust Anchor or intermediate.
pub async fn add_subordinate(entity_id: &str) {
    let data = get_entity_configruation_as_jwt(&entity_id).await;

    self_verify_jwt(&data);
}
