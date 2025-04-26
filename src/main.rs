#![allow(unused)]
use lazy_static::lazy_static;
use redis::Client;
use std::fmt::format;
use std::io;

use actix_web::{
    App, HttpRequest, HttpResponse, HttpServer, Responder, error, get, middleware, web,
};
use serde::Deserialize;
use serde::Serialize;

use josekit::{
    JoseError,
    jwk::{Jwk, JwkSet},
    jws::{JwsHeader, RS256},
    jwt::{self, JwtPayload},
};
use serde_json::{Map, Value, json};
use std::time::{Duration, SystemTime};

lazy_static! {
    static ref PUBLIEC_KEY: Vec<u8> = std::fs::read("./public.json").unwrap();
    static ref PRIVATE_KEY: Vec<u8> = std::fs::read("./private.json").unwrap();
}

fn compile_entityid(iss: &str, sub: &str, metadata: Option<Value>) -> Result<String, JoseError> {
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

async fn get_from_cache(redis: web::Data<redis::Client>) -> actix_web::Result<impl Responder> {
    let mut conn = redis
        .get_connection_manager()
        .await
        .map_err(error::ErrorInternalServerError)?;

    let res = redis::Cmd::get("name")
        .query_async::<String>(&mut conn)
        .await
        .map_err(error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().body(res))
}

#[derive(Serialize, Deserialize)]
pub struct MyParams {
    name: String,
}

async fn cache_stuff(
    req: HttpRequest,
    params: web::Form<MyParams>,
    redis: web::Data<redis::Client>,
) -> actix_web::Result<impl Responder> {
    let mut conn = redis
        .get_connection_manager()
        .await
        .map_err(error::ErrorInternalServerError)?;

    let res = redis::Cmd::set("name", params.name.clone())
        .query_async::<String>(&mut conn)
        .await
        .map_err(error::ErrorInternalServerError)?;

    // not strictly necessary, but successful SET operations return "OK"
    if res == "OK" {
        Ok(HttpResponse::Ok().body("successfully cached values"))
    } else {
        Ok(HttpResponse::InternalServerError().finish())
    }
}

#[get("/")]
async fn index() -> impl Responder {
    "Index page."
}

// This function will read the configuration files in future.
// TODO: maybe returning a better structure from here instead of Value
fn read_configuration() -> Value {
    // HACK: Fixed domain name for now
    let domain = "http://localhost:8080";
    let mut map = Map::new();
    map.insert(
        "federation_fetch_endpoint".to_string(),
        json!(format!("{}/fetch", domain)),
    );

    // list endpoint
    map.insert(
        "federation_list_endpoint".to_string(),
        json!(format!("{}/list", domain)),
    );
    // resolve endpoint
    map.insert(
        "federation_resolve_endpoint".to_string(),
        json!(format!("{}/resolve", domain)),
    );

    // Now the final big map to return
    let mut fed = Map::new();
    fed.insert("federation_entity".to_string(), json!(map));

    json!(fed)
}

/// Sets the given entity_id of the application to the redis server.
/// Thus in future we can return the same entity_id details without creating the JWT again & again.
fn set_app_entity_id(entity_data: &str, redis: Client) {
    let mut conn = redis.get_connection().unwrap();
    let res = redis::Cmd::set("inmor:entity_id", entity_data)
        .query::<String>(&mut conn)
        .unwrap();
}

#[get("/.well-known/openid-federation")]
async fn openid_federation(redis: web::Data<redis::Client>) -> actix_web::Result<impl Responder> {
    let mut conn = redis
        .get_connection_manager()
        .await
        .map_err(error::ErrorInternalServerError)?;

    let res = redis::Cmd::get("inmor:entity_id")
        .query_async::<String>(&mut conn)
        .await
        .map_err(error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok()
        .content_type("application/entity-statement+jwt")
        .body(res))
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    // Start of new signed entity_id for the application
    let meta = read_configuration();
    let entity_data = compile_entityid(
        "http://localhost:8080/",
        "http://localhost:8080",
        Some(meta),
    )
    .unwrap();
    println!("{:?}", entity_data);

    // Now the normal web app flow
    //
    //
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let redis = redis::Client::open("redis://127.0.0.1:6379").unwrap();
    // Here first we set the new entity_id to redis
    set_app_entity_id(&entity_data, redis.clone());

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(redis.clone()))
            .service(
                web::resource("/stuff")
                    .route(web::get().to(get_from_cache))
                    .route(web::post().to(cache_stuff)),
            )
            .service(index)
            .service(openid_federation)
            .wrap(middleware::NormalizePath::trim())
            .wrap(middleware::Logger::default())
    })
    .workers(2)
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
