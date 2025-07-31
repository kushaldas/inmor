#![allow(unused)]
use anyhow::{Result, bail};

use lazy_static::lazy_static;
use log::{debug, info};
use redis::Client;
use reqwest::blocking;
use std::fmt::{Display, format};

use actix_web::{
    App, HttpRequest, HttpResponse, HttpServer, Responder, error, get, middleware, post, web,
};
use actix_web_lab::extract::Query;

use actix_web::http::uri::Parts;
use base64::Engine;
use josekit::{
    JoseError,
    jwk::{Jwk, JwkSet},
    jws::alg::rsassa::RsassaJwsAlgorithm,
    jws::{ES256, ES384, ES512, JwsAlgorithm, JwsHeader, JwsVerifier, PS256, RS256},
    jwt::{self, JwtPayload},
    util,
};
use oidfed_metadata_policy::*;
use serde::Serialize;
use serde::{Deserialize, de::Error};
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};
use std::error::Error as StdError;
use std::ops::Deref;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};
use std::{env, fs};

lazy_static! {
    static ref PUBLIEC_KEY: Vec<u8> = std::fs::read("./public.json").unwrap();
    static ref PRIVATE_KEY: Vec<u8> = std::fs::read("./private.json").unwrap();
}
pub const WELL_KNOWN: &str = ".well-known/openid-federation";

// This struct represents state
pub struct AppState {
    pub entity_id: String,
    pub public_keyset: JwkSet,
}

// To represent the entities in the federation.
// FIXME: add all different data as proper part of the structure.
#[derive(Debug, Clone, Deserialize)]
pub struct EntityDetails {
    pub entity_id: String,
    pub entity_type: String,
    pub has_trustmark: bool,
    pub trustmarks: HashSet<String>,
}

impl EntityDetails {
    pub fn new(entity_id: &str, entity_type: &str, trustmarks: Option<&Value>) -> Self {
        let mut has_trustmark = false;
        let mut tms: HashSet<String> = HashSet::new();

        // https://openid.net/specs/openid-federation-1_0.html#section-7.4
        // Trustmarks is an arrary of objects, with two keys
        // `trust_mark` and `trust_mark_type`.
        if let Some(trustms) = trustmarks {
            // Means we have some trustmarks hopefully
            if let Some(trustmark_array) = trustms.as_array() {
                for one_tm in trustmark_array.iter() {
                    let one_tm_obj = one_tm.as_object().unwrap();
                    if let Some(tm_type) = one_tm_obj.get("trust_mark_type") {
                        tms.insert(tm_type.as_str().unwrap().to_owned());
                    }
                }
            }
        }

        // If we have any trustmarks
        if !tms.is_empty() {
            has_trustmark = true;
        }
        EntityDetails {
            entity_id: entity_id.to_string(),
            entity_type: entity_type.to_string(),
            has_trustmark,
            trustmarks: tms,
        }
    }
}

// This will be shared about threads via AppData
#[derive(Debug, Deserialize)]
pub struct Federation {
    pub entities: Mutex<HashMap<String, EntityDetails>>,
}

// SECTION FOR WEB QUERY PARAMETERS

/// FIXME: get all parameters
#[derive(Debug, Deserialize)]
pub struct ResolveParams {
    sub: String,
    #[serde(rename = "trust_anchor")]
    trust_anchors: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct TrustMarkParams {
    trust_mark_type: String,
    sub: String,
}

#[derive(Debug, Deserialize)]
pub struct TrustMarkListParams {
    trust_mark_type: String,
    sub: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TrustMarkStatusParams {
    trust_mark: String,
}

/// https://openid.net/specs/openid-federation-1_0.html#section-8.2.1
/// All parameters are optional here according to the SPEC.
#[derive(Debug, Serialize, Deserialize)]
pub struct SubListingParams {
    entity_type: Option<Vec<String>>,
    trust_marked: Option<bool>,
    trust_mark_type: Option<String>,
    intermediate: Option<bool>,
}

// QUERY PARAMETERS ENDS

// Response type(s)

/// For https://zachmann.github.io/openid-federation-entity-collection/main.html#section-2.3.2.2

#[derive(Debug, Deserialize, Serialize)]
pub struct EntityCollectionResponse {
    pub entity_id: String,
    pub entity_types: Vec<String>,
}

impl EntityCollectionResponse {
    pub fn new(entity_id: String, entity_types: Vec<String>) -> Self {
        EntityCollectionResponse {
            entity_id,
            entity_types,
        }
    }
}

/// To store each JWT and verified payload from it
/// This will be used to return the final result
#[derive(Debug)]
pub struct VerifiedJWT {
    jwt: String,
    payload: JwtPayload,
    substatement: bool,
    taresult: bool,
}

impl VerifiedJWT {
    pub fn new(jwt: String, payload: &JwtPayload, subs: bool, taresult: bool) -> Self {
        VerifiedJWT {
            jwt,
            payload: payload.clone(),
            substatement: subs,
            taresult,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct URL(String);
impl Deref for URL {
    type Target = String;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for URL {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Clone for URL {
    fn clone(&self) -> Self {
        URL(self.0.clone())
    }
}

// TODO: encode the OpenID spec's requirements into the type system. Not to do runtime validation (primarily)
//      but to ensure that developers pass the correct properties to the correct places.
//      For now everything is just URL but the specs allows different things for different endpoints.
//      See e.g. https://openid.net/specs/openid-federation-1_0.html#section-5.1.1-4.2

#[derive(Debug, Deserialize)]
pub struct Endpoints {
    fetch: URL,
    list: URL,
    resolve: URL,
    collection: URL,
    // trust_mark_status: URL,
    // trust_mark_list: URL,
    // trust_mark: URL,
    // historical_keys: URL,
    // auth_signing_alg_values_supported: URL,
    // signed_jwks_uri: URL,
}

impl Endpoints {
    pub fn to_openid_metadata(&self) -> Value {
        let mut ret = Map::new();
        ret.insert("federation_fetch_endpoint".to_string(), json!(self.fetch));
        ret.insert("federation_list_endpoint".to_string(), json!(self.list));
        ret.insert(
            "federation_resolve_endpoint".to_string(),
            json!(self.resolve),
        );

        ret.insert(
            "federation_collection_endpoint".to_string(),
            json!(self.collection),
        );
        json!(ret)
    }

    pub fn from_domain(domain: &str) -> Self {
        Self {
            fetch: URL(format!("{domain}/fetch")),
            list: URL(format!("{domain}/list")),
            resolve: URL(format!("{domain}/resolve")),
            collection: URL(format!("{domain}/collection")),
        }
    }
}

impl Default for Endpoints {
    fn default() -> Self {
        Self::from_domain("0.0.0.0")
    }
}

#[derive(Debug, Deserialize)]
pub struct ServerConfiguration {
    pub domain: URL,
    pub redis_uri: String,

    #[serde(skip)]
    pub endpoints: Endpoints,
}

impl ServerConfiguration {
    pub fn new(domain: String, redis_uri: String) -> ServerConfiguration {
        let endpoints = Endpoints {
            fetch: URL(format!("{domain}/fetch")),
            list: URL(format!("{domain}/list")),
            resolve: URL(format!("{domain}/resolve")),
            collection: URL(format!("{domain}/collection")),
        };
        ServerConfiguration {
            domain: URL(domain),
            endpoints,
            redis_uri,
        }
    }

    pub fn from_toml(toml_path: &str) -> Result<Self, Box<dyn StdError>> {
        let config_string = fs::read_to_string(toml_path)?;
        let intermediate: ServerConfiguration = toml::from_str(config_string.as_str())?;
        let endpoints = Endpoints::from_domain(&intermediate.domain);
        Ok(Self {
            endpoints,
            ..intermediate
        })
    }

    // Constructs an instance of ServerConfiguration by fetching required values from env vars
    pub fn from_env() -> ServerConfiguration {
        let domain = env::var("TA_DOMAIN").unwrap_or("http://localhost:8080".to_string());
        let redis = env::var("TA_REDIS").unwrap_or("redis://redis:6379".to_string());
        ServerConfiguration::new(domain, redis)
    }
}

// TODO: There is only key here, in future we will need
// to handle multiple keys so that we have a proper keyset.
/// To create a JwkSet for the public keys of the TA
pub fn get_ta_jwks_public_keyset() -> JwkSet {
    let mut keymap = Map::new();
    let public_keydata = &*PUBLIEC_KEY.clone();
    let publickey = Jwk::from_bytes(public_keydata).unwrap();
    let mut keys: Vec<Value> = Vec::new();
    let map: Map<String, Value> = publickey.as_ref().clone();
    keys.push(json!(map));
    // Now outer map
    keymap.insert("keys".to_string(), json!(keys));

    JwkSet::from_map(keymap).unwrap()
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
    let _ = payload.set_claim("metadata", metadata);

    // Signing JWT
    let keydata = &*PRIVATE_KEY.clone();
    let key = Jwk::from_bytes(keydata).unwrap();

    let signer = RS256.signer_from_jwk(&key)?;
    let jwt = jwt::encode_with_signer(&payload, &header, &signer)?;
    Ok(jwt)
}

/// This method returns the corresponding entitys based on given
/// entity type. Used in fetch_collection endpoint.
pub async fn get_entitycollectionresponse(
    entity_type: &str,
    redis: web::Data<redis::Client>,
) -> Result<Vec<EntityCollectionResponse>> {
    // FIXME: take care of the unwrap here
    let mut conn = redis.get_connection_manager().await.unwrap();
    let mut result: Vec<EntityCollectionResponse> = Vec::new();
    match entity_type {
        "openid_provider" => {
            let mut res = (redis::Cmd::smembers("inmor:op")
                .query_async::<Vec<String>>(&mut conn)
                .await)
                .unwrap_or_default();
            // Now loop over
            for entry in res {
                let entry_struct = EntityCollectionResponse::new(
                    entry,
                    vec![
                        "federation_entity".to_string(),
                        "openid_provider".to_string(),
                    ],
                );
                result.push(entry_struct);
            }
        }
        "openid_relying_party" => {
            let mut res = (redis::Cmd::smembers("inmor:rp")
                .query_async::<Vec<String>>(&mut conn)
                .await)
                .unwrap_or_default();
            // Now loop over
            for entry in res {
                let entry_struct = EntityCollectionResponse::new(
                    entry,
                    vec![
                        "federation_entity".to_string(),
                        "openid_relying_party".to_string(),
                    ],
                );
                result.push(entry_struct);
            }
        }
        "taia" => {
            let mut res = (redis::Cmd::smembers("inmor:taia")
                .query_async::<Vec<String>>(&mut conn)
                .await)
                .unwrap_or_default();
            // Now loop over
            for entry in res {
                let entry_struct =
                    EntityCollectionResponse::new(entry, vec!["federation_entity".to_string()]);
                result.push(entry_struct);
            }
        }
        _ => (),
    }
    Ok(result)
}

/// TODO: We need to deal with query parameters in future
/// https://openid.net/specs/openid-federation-1_0.html#section-8.2.1
#[get("/list")]
async fn list_subordinates(
    info: Query<SubListingParams>,
    data: web::Data<Federation>,
) -> actix_web::Result<impl Responder> {
    let SubListingParams {
        entity_type,
        trust_marked,
        trust_mark_type,
        intermediate,
    } = info.into_inner();

    // This will contain all subordinates without filtering
    let mut results: Vec<EntityDetails> = Vec::new();
    {
        let fed = data.entities.lock().unwrap();
        for (key, val) in fed.iter() {
            results.push(val.clone());
        }
    }
    // Now let us go through the list if we need to filter based on the query parameter.
    if let Some(etype) = entity_type {
        // Means an entity_type was passed.
        results.retain(|x| etype.contains(&x.entity_type));
    }

    if let Some(inter) = intermediate {
        // Means we should only provide any intermediate subordinate
        results.retain(|x| match x.entity_type.as_str() {
            "taia" => inter, // When we asked for intermediate
            _ => !inter,     // When we want to the rest
        });
    }

    if let Some(trust_marked) = trust_marked {
        // Means check if at least one trustmark exists
        results.retain(|x| x.has_trustmark);
    }

    let res: Vec<String> = results.iter().map(|x| x.entity_id.clone()).collect();
    Ok(HttpResponse::Ok().json(res))
}

///https://zachmann.github.io/openid-federation-entity-collection/main.html
/// Entity collection endpoint, from Zachmann's draft.
#[get("/collection")]
pub async fn fetch_collections(
    req: HttpRequest,
    redis: web::Data<redis::Client>,
) -> actix_web::Result<impl Responder> {
    let params: Vec<(String, String)> =
        match web::Query::<Vec<(String, String)>>::from_query(req.query_string()) {
            Ok(data) => data.to_vec(),
            Err(_) => return Err(error::ErrorBadRequest("Missing params")),
        };

    let mut conn = redis
        .get_connection_manager()
        .await
        .map_err(error::ErrorInternalServerError)?;

    let mut entity_type_asked = false;

    let mut result: Vec<EntityCollectionResponse> = Vec::new();
    for (q, p) in params.iter() {
        if (q == "entity_type") {
            // Means we were asked an entity type
            entity_type_asked = true;
            match p.as_str() {
                "openid_provider" => {
                    let internal = get_entitycollectionresponse("openid_provider", redis.clone())
                        .await
                        .map_err(error::ErrorInternalServerError)?;
                    result.extend(internal);
                }
                "openid_relying_party" => {
                    let internal =
                        get_entitycollectionresponse("openid_relying_party", redis.clone())
                            .await
                            .map_err(error::ErrorInternalServerError)?;
                    result.extend(internal);
                }

                _ => (),
            }
        } else {
            // We don't support the other query parameters yet.
            // https://zachmann.github.io/openid-federation-entity-collection/main.html#section-2.2.1 has all
            // the details.
            return error_response_400("unsupported_parameter", "{q}");
        }
    }

    // If no entity type was asked, we should return all types.
    if !entity_type_asked {
        let internal = get_entitycollectionresponse("openid_provider", redis.clone())
            .await
            .map_err(error::ErrorInternalServerError)?;
        result.extend(internal);
        let internal = get_entitycollectionresponse("openid_relying_party", redis.clone())
            .await
            .map_err(error::ErrorInternalServerError)?;
        result.extend(internal);

        let internal = get_entitycollectionresponse("taia", redis)
            .await
            .map_err(error::ErrorInternalServerError)?;
        result.extend(internal);
    }

    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .body(json!(result).to_string()))
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

    let res = match redis::Cmd::hget("inmor:subordinates", sub)
        .query_async::<String>(&mut conn)
        .await
    {
        Ok(data) => data,
        Err(_) => return error_response_404("not_found", "Subordinate not found."),
    };

    Ok(HttpResponse::Ok()
        .content_type("application/entity-statement+jwt")
        .body(res))
}

/// Get JWK Set from the given payload
pub fn get_jwks_from_payload(payload: &JwtPayload) -> Result<JwkSet> {
    let jwks_data = match payload.claim("jwks") {
        Some(data) => data,
        None => return Err(anyhow::Error::msg("No jwks was found in the payload")),
    };
    let keys = match jwks_data.get("keys") {
        Some(data) => data,
        None => {
            return Err(anyhow::Error::msg(
                "No keys was found in jwks in the payload",
            ));
        }
    };
    let mut internal_map: Map<String, Value> = Map::new();
    internal_map.insert("keys".to_string(), keys.clone());

    Ok(JwkSet::from_map(internal_map)?)
}

/// Gets the payload and header without any cryptographic verification.
#[allow(clippy::explicit_counter_loop)]
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
pub fn verify_jwt_with_jwks(data: &str, keys: Option<JwkSet>) -> Result<(JwtPayload, JwsHeader)> {
    // Code to find the header & payload without any verification
    let (payload, header) = get_unverified_payload_header(data); // Now either use the passed one or use self keys
    let jwks = match keys {
        Some(d) => d,
        None => get_jwks_from_payload(&payload)?,
    };
    // FIXME: veify it exits
    let kid = header.key_id().unwrap();
    // Let us find the key used to sign the JWT
    let key = jwks.get(kid)[0];
    // FIXME: We need different verifiers for different kinds of
    // JWK.
    //println!("ALGO: {:?}", header.algorithm().unwrap());
    let boxed_verifier: Box<dyn JwsVerifier> = match header.algorithm().unwrap() {
        "RS256" => Box::new(RS256.verifier_from_jwk(key).unwrap()),
        "PS256" => Box::new(PS256.verifier_from_jwk(key).unwrap()),
        "ES256" => Box::new(ES256.verifier_from_jwk(key).unwrap()),
        "ES384" => Box::new(ES384.verifier_from_jwk(key).unwrap()),
        // FIXME: This has to be fixed for all different keys
        _ => Box::new(ES512.verifier_from_jwk(key).unwrap()),
    };
    let verifier = &*boxed_verifier;
    let (payload, header) = jwt::decode_with_verifier(data, verifier)?;
    Ok((payload, header))
}

/// This function will self veify the JWT and returns
/// the payload and header after verification.
pub fn self_verify_jwt(data: &str) -> Result<(JwtPayload, JwsHeader)> {
    let (payload, header) = get_unverified_payload_header(data);
    let jwks = get_jwks_from_payload(&payload)?;
    let (payload, header) = verify_jwt_with_jwks(data, Some(jwks))?;
    Ok((payload, header))
}

/// This function will walk through a subordinate's tree of entities.
/// Means you point it to a TA/IA and it will traverse the whole tree.
pub fn tree_walking(entity_id: &str, conn: &mut redis::Connection) {
    // First let us get the entity configuration
    let jwt_net = match get_jwt_sync(entity_id) {
        Ok(res) => res,
        Err(_) => return,
    };

    // Verify and get the payload
    let (entity_payload, _) = match self_verify_jwt(&jwt_net) {
        Ok(data) => data,
        Err(_) => return,
    };

    // Add to the visisted list
    match redis::Cmd::sadd("inmor:current_visited", entity_id).query::<String>(conn) {
        Ok(_) => (),
        Err(e) => return,
    }
    // Add to the entity hash in redis
    match redis::Cmd::hset("inmor:entities", entity_id, jwt_net.as_bytes()).query::<String>(conn) {
        Ok(_) => (),
        Err(e) => return,
    }

    // Visit authorities for authority statements
    if let Some(value) = entity_payload.claim("authority_hints") {
        // We need to traverse the authorities
        fetch_all_subordinate_statements(value, entity_id, conn);
    }

    // Now the actual discovery
    let metadata = match entity_payload.claim("metadata") {
        Some(value) => value.as_object().unwrap(),
        None => return,
    };

    if metadata.get("openid_relying_party").is_some() {
        // Means RP
        let _ = redis::Cmd::sadd("inmor:rp", entity_id).query::<String>(conn);
    } else if metadata.get("openid_provider").is_some() {
        // Means OP

        match redis::Cmd::sadd("inmor:op", entity_id).query::<String>(conn) {
            Ok(_) => (),
            Err(_) => return,
        }
    } else {
        // Means a TA/IA.
        match redis::Cmd::sadd("inmor:taia", entity_id).query::<String>(conn) {
            Ok(_) => (),
            Err(_) => return,
        }
        // Getting the list endpoint if any
        let list_endpoint = match metadata.get("federation_entity") {
            Some(f_entity) => f_entity.get("federation_list_endpoint"),
            None => None,
        };

        if list_endpoint.is_none() {
            // Means no list endpoint avaiable
            // TODO: add debug point here
            return;
        }
        match get_query_sync(list_endpoint.unwrap().as_str().unwrap()) {
            Ok(resp) => {
                // Here we will loop through the subordinates
                let subs: Value = serde_json::from_str(&resp).unwrap();
                for sub in subs.as_array().unwrap() {
                    let sub_str = sub.as_str().unwrap();
                    let ismember = redis::Cmd::sismember("inmor:current_visited", sub_str)
                        .query::<bool>(conn)
                        .unwrap_or_default();
                    if ismember {
                        // Means we already visited it, it is a loop
                        // We should skip it.
                        info!("We have a loop: {sub_str}");
                        continue;
                    }
                    // Means we have a new subordinate
                    info!("Found new subordinate: {sub_str}");
                    queue_lpush(sub_str, conn);
                }
            }
            Err(_) => return,
        }
    }
}

// To push to the queue for the next set of visists
pub fn queue_lpush(entity_id: &str, conn: &mut redis::Connection) {
    redis::Cmd::lpush("inmor:visit_subordinate", entity_id)
        .query::<bool>(conn)
        .unwrap_or_default();
}

// To blocked wait on the queue
pub fn queue_wait(conn: &mut redis::Connection) -> String {
    match redis::Cmd::brpop("inmor:visit_subordinate", 0.0).query::<(String, String)>(conn) {
        Ok(val) => {
            println!("Received {val:?} inside.");
            val.1
        }
        Err(e) => {
            println!("{e:?}");
            "".to_string()
        }
    }
}

/// Fetches the subordinate statements and stores on memory as required.
pub fn fetch_all_subordinate_statements(
    authority_hints: &Value,
    entity_id: &str,
    conn: &mut redis::Connection,
) {
    let ahints = authority_hints.as_array().unwrap();
    for ahint in ahints.iter() {
        let ahint_str = ahint.as_str().unwrap();
        // HACK: Enable TA hack here
        // TODO: ^^
        println!("Fetching {ahint_str:?}");
        let jwt_net = match get_jwt_sync(ahint_str) {
            Ok(res) => res,
            Err(_) => return,
        };

        // Verify and get the payload
        let (entity_payload, _) = match self_verify_jwt(&jwt_net) {
            Ok(data) => data,
            Err(_) => return,
        };

        let metadata = match entity_payload.claim("metadata") {
            Some(value) => value.as_object().unwrap(),
            None => continue,
        };

        // First get the federation_entity map inside of the JSOn
        let fed_entity = match metadata.get("federation_entity") {
            Some(value) => value.as_object().unwrap(),
            None => continue,
        };
        // Then the fetch_end_point
        let fetch_endpoint = fed_entity.get("federation_fetch_endpoint");

        println!("SEE {fetch_endpoint:?}");
        if fetch_endpoint.is_some() {
            // HACK: Enable TA hack here
            // TODO: ^^
            let fetch_endpoint = fetch_endpoint.unwrap();
            let sub_statement =
                fetch_sub_statement_sync(fetch_endpoint.as_str().unwrap(), entity_id);
            if let Ok((jwt_str, url)) = sub_statement {
                // Store it on memeory
                match redis::Cmd::hset("inmor:subordinate_query", url, jwt_str.as_bytes())
                    .query::<String>(conn)
                {
                    Ok(_) => (),
                    Err(e) => return,
                }
            }
        }
    }
}

pub async fn resolve_entity_to_trustanchor(
    sub: &str,
    trust_anchors: Vec<&str>,
    start: bool,
    visited: &mut HashSet<String>,
) -> Result<Vec<VerifiedJWT>> {
    eprintln!("\nReceived {sub} with trust anchors {trust_anchors:?}");

    let empty_authority: Vec<String> = Vec::new();
    let eal = json!(empty_authority);

    // This will hold the list of trust chain
    let mut result = Vec::new();

    // to stop infinite loop
    // First get the entity configuration and self verify
    let original_ec = match get_entity_configruation_as_jwt(sub).await {
        Ok(res) => res,
        Err(_) => return Ok(result), // Read FOUND_TA section in code to find why it is okay to
                                     // result a half done list back.
    };
    // Add it already visited
    visited.insert(sub.to_string());

    let (opayload, oheader) = self_verify_jwt(&original_ec)?;

    if start {
        let vjwt = VerifiedJWT::new(original_ec, &opayload, false, false);
        result.push(vjwt);
    }
    // Now find the authority_hints
    let authority_hints = match opayload.claim("authority_hints") {
        Some(v) => v,
        // Means we are at one Trust anchor (most probably)
        None => &eal,
    };
    println!("\nAuthority hints: {authority_hints:?}\n");
    // Loop over the authority hints
    for ah in authority_hints.as_array().unwrap() {
        // Flag to mark if we found the trust anchor
        let mut ta_flag = false;
        // Get the str from the JSON value
        let ah_entity: &str = ah.as_str().unwrap();
        // If we already visited the authority then continue
        if visited.contains(ah_entity) {
            continue;
        }
        // If this is one of the trust anchor, then we are done
        if trust_anchors.contains(&ah_entity) {
            // Means we found our trust anchor
            ta_flag = true;
        }
        // Fetch the authority's entity configuration
        let ah_jwt = match get_entity_configruation_as_jwt(ah_entity).await {
            Ok(res) => res,
            Err(_) => return Ok(result), // Read FOUND_TA section in code to find why it is okay to
                                         // result a half done list back.
        };

        // Verify and get the payload
        let (ah_payload, _) = self_verify_jwt(&ah_jwt).unwrap();
        // Now find the fetch endpoint
        let ah_metadata = ah_payload.claim("metadata").unwrap();
        let fetch_endpoint = ah_metadata
            .get("federation_entity")
            .unwrap()
            .get("federation_fetch_endpoint")
            .unwrap();
        // Fetch the entity statement/ subordinate statement
        let sub_statement =
            match fetch_subordinate_statement(fetch_endpoint.as_str().unwrap(), sub).await {
                Ok(res) => res,
                Err(_) => return Ok(result), // Read FOUND_TA section in code to find why it is okay to
                                             // result a half done list back.
            };
        // Get the authority's JWKS and then verify the subordinate statement against them.
        let ah_jwks = match get_jwks_from_payload(&ah_payload) {
            Ok(result) => result,
            Err(_) => continue,
        };
        let (subs_payload, _) = match verify_jwt_with_jwks(&sub_statement, Some(ah_jwks)) {
            Ok(value) => value,
            Err(_) => continue,
        };
        // The above function verify_jwt_with_jwks now has error handling part.
        if ta_flag {
            // Means this is the end of resolving
            let vjwt = VerifiedJWT::new(sub_statement, &subs_payload, true, false);
            result.push(vjwt);
            let ajwt = VerifiedJWT::new(ah_jwt.clone(), &ah_payload, false, true);
            result.push(ajwt);
            return Ok(result);
        } else {
            // Now do a recursive query
            let r_result = Box::pin(resolve_entity_to_trustanchor(
                ah_entity,
                trust_anchors.clone(),
                false,
                visited,
            ))
            .await?;
            if r_result.is_empty() {
                continue;
            } else {
                let vjwt = VerifiedJWT::new(sub_statement, &subs_payload, true, false);
                result.push(vjwt);
                result.extend(r_result);
            }
            return Ok(result);
        }
    }
    Ok(vec![])
}

/// To create the signed JWT for resolve response
fn create_resolve_response_jwt(
    state: &web::Data<AppState>,
    sub: &str,
    result: &[VerifiedJWT],
    metadata: Option<Map<String, Value>>,
) -> Result<String, JoseError> {
    let mut header = JwsHeader::new();
    header.set_token_type("JWT");
    header.set_claim("typ", Some(json!("resolve-response+jwt")));
    header.set_claim("alg", Some(json!("RS256")));

    let mut payload = JwtPayload::new();
    let iss = state.entity_id.clone();
    payload.set_issuer(iss);
    payload.set_subject(sub);
    payload.set_issued_at(&SystemTime::now());

    // Set expiry after 24 horus
    let exp = SystemTime::now() + Duration::from_secs(86400);
    payload.set_expires_at(&exp);
    payload.set_claim("metadata", Some(json!(metadata)));
    let trust_chain: Vec<String> = result.iter().map(|x| x.jwt.clone()).collect();
    let _ = payload.set_claim("trust_chain", Some(json!(trust_chain)));

    // Signing JWT
    let keydata = &*PRIVATE_KEY.clone();
    let key = Jwk::from_bytes(keydata).unwrap();

    let signer = RS256.signer_from_jwk(&key)?;
    let jwt = jwt::encode_with_signer(&payload, &header, &signer)?;
    Ok(jwt)
}

/// https://openid.net/specs/openid-federation-1_0.html#name-resolve-request
#[get("/resolve")]
pub async fn resolve_entity(
    info: Query<ResolveParams>,
    redis: web::Data<redis::Client>,
    state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    let mut found_ta = false;
    let ResolveParams { sub, trust_anchors } = info.into_inner();
    let tas: Vec<&str> = trust_anchors.iter().map(|s| s as &str).collect();
    let mut visisted: HashSet<String> = HashSet::new();
    // Now loop over the trust_anchors
    let result = match resolve_entity_to_trustanchor(&sub, tas, true, &mut visisted).await {
        Ok(res) => res,
        Err(_) => {
            return error_response_400("invalid_trust_chain", "Failed to find trust chain");
        }
    };

    // Verify that the result is not empty and we actually found a TA
    if result.is_empty() {
        return error_response_400("invalid_trust_chain", "Failed to find trust chain");
    }
    if result.iter().any(|i| i.taresult) {
        // Means we found our trust anchor
        // FOUND_TA: Here if verify if we actually found any of the TA we wanted.
        found_ta = true;
    }
    if !found_ta {
        return error_response_400("invalid_trust_chain", "Failed to find trust chain");
    }

    let mut mpolicy: Option<Map<String, Value>> = None;
    // We need to skip the top one (the trust anchor's entity configuration)
    for res in result.iter().rev().skip(1) {
        println!("\n{:?}\n", res.payload);
        mpolicy = match mpolicy {
            // This is when we have some policy the higher subordinate statement
            Some(mut val) => {
                // But we should only apply claim from subordinate statements
                if res.substatement {
                    let new_policy = res.payload.claim("metadata_policy");
                    match new_policy {
                        Some(p) => {
                            let temp_val = json!(val);
                            // Uncomment these to learn about metadata policy merging
                            //println!("\n Calling with {:?}\n\n{:?}\n\n\n", &temp_val, p);
                            let merged = merge_policies(&temp_val, p);
                            match merged {
                                Ok(policy) => Some(policy),
                                Err(_) => {
                                    return error_response_400(
                                        "invalid_trust_chain",
                                        "Failed in merging metadata policy",
                                    );
                                }
                            }
                        }
                        None => Some(val),
                    }
                } else {
                    // Means the final entity statement
                    // We should now apply the merged policy at val to the metadata claim
                    let mut meta_keys: HashSet<String> = HashSet::new();
                    let metadata = res.payload.claim("metadata").unwrap().as_object().unwrap();
                    eprintln!(
                        "\nFinal policy checking: val= {:?}\n\n metadata= {:?}\n\n",
                        &val, metadata
                    );
                    // If the particular key of metadata exists in policy, then only we apply the
                    // policy on the metata
                    for (mkey, mvalue) in metadata.iter() {
                        // Check for the key
                        if val.contains_key(mkey) {
                            // Now we need that particular policy and actual metadata for that
                            // part.
                            let mpolicy = val.get(mkey).unwrap().as_object().unwrap();
                            let result =
                                resolve_metadata_policy(mpolicy, mvalue.as_object().unwrap());
                            // Now we have the result for one particular metadata
                            // If it is Okay, then we should put the resolved metadata to the val
                            //
                            match result {
                                Ok(v) => {
                                    let temp = v.as_object().unwrap().get(mkey).unwrap();
                                    val.insert(mkey.clone(), temp.clone());
                                    // Now keep a note that we have used this key
                                    meta_keys.insert(mkey.clone());
                                }
                                Err(_) => {
                                    return error_response_400(
                                        "invalid_trust_chain",
                                        "received error in applying metadata policy on metadata",
                                    );
                                }
                            }
                        } else {
                            // Here the policy object does not have the key of the metadata, means
                            // we directly copy it over.
                            meta_keys.insert(mkey.clone());
                            val.insert(mkey.clone(), mvalue.clone());
                        }
                    }

                    // Now remove any extra key/value pair from the final resolved metadata.
                    // These extra key/values were part of policy but does not matter for this
                    // metadata.
                    let mut to_remove = Vec::new();
                    for (key, _) in val.iter() {
                        if !meta_keys.contains(key) {
                            // Then remove it
                            to_remove.push(key.clone());
                        }
                    }
                    // Now all extra key/value
                    for key in to_remove.iter() {
                        val.remove(key);
                    }
                    //
                    println!("Succesfully applied metadata policy on metadata");
                    println!("{:?}\n", &val);

                    // No error, all good.
                    Some(val)
                }
            }

            // Means first time getting a metadata policy.
            // We should store it properly in mpolicy
            None => {
                // We should only get it from a subordinate statement
                if res.substatement {
                    let new_policy = res.payload.claim("metadata_policy");
                    match new_policy {
                        Some(p) => {
                            let data = p.as_object().unwrap().clone();
                            Some(data)
                        }

                        // Even the subordinate statement does not have any policy
                        None => Some(Map::new()),
                    }
                } else {
                    // Not a subordinate statement
                    // Means an entity statement
                    // Means no policy and only statement, nothing to verify against
                    // Return the original metadata here
                    //None
                    //Some(Map::new())
                    Some(
                        res.payload
                            .claim("metadata")
                            .unwrap()
                            .as_object()
                            .unwrap()
                            .clone(),
                    )
                }
            }
        };
    }
    // HACK:
    println!("After the whole call: {mpolicy:?}\n");
    // If we reach here means we have a list of JWTs and also verified metadata.
    // TODO: deal with the signing error here.
    let resp = create_resolve_response_jwt(&state, &sub, &result, mpolicy).unwrap();
    Ok(HttpResponse::Ok()
        .insert_header(("content-type", "application/resolve-response+jwt"))
        .body(resp))
}

/// https://openid.net/specs/openid-federation-1_0.html#section-8.4.1
#[get("/trust_mark_status")]
pub async fn trust_mark_status(
    info: Query<TrustMarkStatusParams>,
    redis: web::Data<redis::Client>,
    state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    let TrustMarkStatusParams { trust_mark } = info.into_inner();

    let jwks = state.public_keyset.clone();
    let (payload, _) = match verify_jwt_with_jwks(&trust_mark, Some(jwks)) {
        Ok(d) => d,
        Err(err) => {
            return error_response_400("invalid_request", "Could not verify the request");
        }
    };

    //
    let mut result = HashMap::new();
    result.insert("active", true);
    let body = match serde_json::to_string(&result) {
        Ok(d) => d,
        Err(_) => return Err(error::ErrorInternalServerError("JSON error")),
    };
    Ok(HttpResponse::Ok()
        .insert_header(("content-type", "application/json"))
        .body(body))
}

/// https://openid.net/specs/openid-federation-1_0.html#section-8.5.1
#[get("/trust_marked_list")]
pub async fn trust_marked_list(
    info: Query<TrustMarkListParams>,
    redis: web::Data<redis::Client>,
    state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    let TrustMarkListParams {
        trust_mark_type,
        sub,
    } = info.into_inner();

    let mut conn = redis
        .get_connection_manager()
        .await
        .map_err(error::ErrorInternalServerError)?;

    let query = format!("inmor:tmtype:{trust_mark_type}");

    let res = redis::Cmd::smembers(query)
        .query_async::<Vec<String>>(&mut conn)
        .await
        .map_err(error::ErrorInternalServerError);
    if res.is_err() {
        Ok(HttpResponse::NotFound().body(""))
    } else {
        let mut result = res.unwrap();
        if sub.is_some() {
            // Means we have a sub value to check
            let sub_entity = sub.unwrap();
            if result.contains(&sub_entity) {
                result = vec![sub_entity];
            } else {
                // Means so such sub for the trust_mark_type in redis
                return Ok(HttpResponse::NotFound().body(""));
            }
        }

        let body = match serde_json::to_string(&result) {
            Ok(d) => d,
            Err(_) => return Err(error::ErrorInternalServerError("JSON error")),
        };
        Ok(HttpResponse::Ok()
            .insert_header(("content-type", "application/json"))
            .body(body))
    }
}

///
/// https://openid.net/specs/openid-federation-1_0.html#section-8.6.1
#[get("/trust_mark")]
pub async fn trust_mark_query(
    info: Query<TrustMarkParams>,
    redis: web::Data<redis::Client>,
    state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    let TrustMarkParams {
        trust_mark_type,
        sub,
    } = info.into_inner();

    let mut conn = redis
        .get_connection_manager()
        .await
        .map_err(error::ErrorInternalServerError)?;

    let query = format!("inmor:tm:{sub}");

    let res = redis::Cmd::hget(query, trust_mark_type)
        .query_async::<String>(&mut conn)
        .await
        .map_err(error::ErrorInternalServerError);
    match res {
        Ok(result) => Ok(HttpResponse::Ok()
            .insert_header(("content-type", "application/trust-mark+jwt"))
            .body(result)),
        Err(_) => error_response_404("not_found", "Trust mark not found."),
    }
}

/// Fetches the subordinate statement from authority
pub async fn fetch_subordinate_statement(fetch_url: &str, entity_id: &str) -> Result<String> {
    let url = format!("{fetch_url}?sub={entity_id}");
    debug!("FETCH {url}");
    return get_query(&url).await;
}

/// Get the entity configuration for a given entity_id
pub async fn get_entity_configruation_as_jwt(entity_id: &str) -> Result<String> {
    let url = format!("{entity_id}/{WELL_KNOWN}");
    debug!("EC {url}");
    return get_query(&url).await;
}

/// Gets subordinate statement in sync
pub fn fetch_sub_statement_sync(fetch_url: &str, entity_id: &str) -> Result<(String, String)> {
    let url = format!("{fetch_url}?sub={entity_id}");
    debug!("FETCH {url}");
    match get_query_sync(&url) {
        Ok(res) => Ok((res, url)),
        Err(e) => Err(e),
    }
}

/// Gets the enitity configuration of a given entity_id for sync code.
pub fn get_jwt_sync(entity_id: &str) -> Result<String> {
    let url = format!("{entity_id}/{WELL_KNOWN}");
    get_query_sync(&url)
}

/// GET call for sync code
pub fn get_query_sync(url: &str) -> Result<String> {
    let resp = match ureq::get(url).call() {
        Ok(mut body) => body.body_mut().read_to_string()?,
        Err(e) => return Err(anyhow::Error::new(e)),
    };
    Ok(resp)
}

/// To do a GET query
pub async fn get_query(url: &str) -> Result<String> {
    Ok(reqwest::get(url).await?.text().await?)
}

/// FIXME: as an example.
/// This function will add a new sub-ordinate entity to
/// a Trust Anchor or intermediate.
pub async fn add_subordinate(entity_id: &str) -> Result<String> {
    let data = get_entity_configruation_as_jwt(entity_id).await?;

    self_verify_jwt(&data);
    Ok("all good".to_string())
}

pub fn error_response_404(edetails: &str, message: &str) -> actix_web::Result<HttpResponse> {
    Ok(HttpResponse::NotFound()
        .content_type("application/json")
        .body(format!(
            "{{\"error\":\"{edetails}\",\"error_description\": \"{message}\"}}"
        )))
}

pub fn error_response_400(edetails: &str, message: &str) -> actix_web::Result<HttpResponse> {
    Ok(HttpResponse::BadRequest()
        .content_type("application/json")
        .body(format!(
            "{{\"error\":\"{edetails}\",\"error_description\": \"{message}\"}}"
        )))
}
