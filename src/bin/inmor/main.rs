#![allow(unused)]

use actix_web::{
    App, HttpRequest, HttpResponse, HttpServer, Responder, error, get, middleware, web,
};
use lazy_static::lazy_static;
use redis::Client;
use redis::Commands;
use serde::Deserialize;
use serde::Serialize;
use std::fmt::format;
use std::fs;
use std::ops::Deref;
use std::sync::Mutex;
use std::{env, io};

use clap::Parser;
use inmor::*;
use josekit::{
    JoseError,
    jwk::{Jwk, JwkSet},
    jws::{JwsHeader, RS256},
    jwt::{self, JwtPayload},
};
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

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

/// Sets the given entity_id of the application to the redis server.
/// Thus in future we can return the same entity_id details without creating the JWT again & again.
fn set_app_entity_data(entity_data: &str, redis: &Client) {
    let mut conn = redis.get_connection().unwrap();
    let res = redis::Cmd::set("inmor:entity_id", entity_data)
        .query::<String>(&mut conn)
        .unwrap();
}

/// https://openid.net/specs/openid-federation-1_0.html#name-entity-statement
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

#[derive(Parser, Debug)]
#[command(version(env!("CARGO_PKG_VERSION")), about(env!("CARGO_PKG_DESCRIPTION")))]
struct Cli {
    #[arg(
        short = 'c',
        long = "config",
        value_name = "FILE",
        help = "Configuration file for the server in .toml format"
    )]
    toml_file_path: String,
    #[arg(short, long, default_value_t = 8080, help = "Port to run the server")]
    port: u16,
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    let args = Cli::parse();
    let port = args.port;
    let toml_file_path = args.toml_file_path;
    let server_config = ServerConfiguration::from_toml(&toml_file_path).unwrap_or_else(|_| {
        panic!(
            "Failed reading server configuration from {}.",
            &toml_file_path
        )
    });

    // Start of new signed entity_id for the application
    let mut federation_entity = Map::new();
    federation_entity.insert(
        "federation_entity".to_string(),
        server_config.endpoints.to_openid_metadata(),
    );
    let entity_data = compile_entityid(
        &format!("{}/", &server_config.domain),
        &server_config.domain,
        json!(federation_entity).into(),
    )
    .unwrap();
    println!("{entity_data:?}");

    // Now the normal web app flow
    //
    //
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    let redis = redis::Client::open(server_config.redis_uri.as_str()).unwrap();
    // Here first we set the new entity_id to redis
    set_app_entity_data(&entity_data, &redis);

    let mut federation = Federation {
        entities: Mutex::new(HashMap::new()),
    };

    // Now we will go through all the subordinates from admin application
    //let file_data = fs::read_to_string("subordinates.json").expect("Cound not read.");
    //let new_skolor: Federation =
    //serde_json::from_str(&file_data).expect("JSON is not well formatted");

    let mut con = redis.get_connection().unwrap();
    let entities: HashMap<String, String> = con.hgetall("inmor:subordinates:jwt").unwrap();
    {
        let mut fe = federation.entities.lock().unwrap();
        for (key, val) in entities.iter() {
            // Let us get the metadata
            let (payload, _) = get_unverified_payload_header(val);
            let metadata = payload.claim("metadata").unwrap();
            let trustmarks = payload.claim("trust_marks");
            let x = metadata.as_object().unwrap();
            if x.contains_key("openid_provider") {
                // Means OP
                let entity = EntityDetails::new(key, "openid_provider", trustmarks);
                fe.insert(key.clone(), entity);
            } else if x.contains_key("openid_relying_party") {
                // Means RP
                let entity = EntityDetails::new(key, "openid_relying_party", trustmarks);

                fe.insert(key.clone(), entity);
            } else {
                // Means TA/IA
                let entity = EntityDetails::new(key, "taia", trustmarks);
                fe.insert(key.clone(), entity);
            }
        }
    }

    // End of loop for finding all subordinates
    //
    let fed_app_data = web::Data::new(federation);

    HttpServer::new(move || {
        //
        let jwks = get_ta_jwks_public_keyset();
        //
        App::new()
            .app_data(web::Data::new(AppState {
                entity_id: server_config.domain.to_string(),
                public_keyset: jwks,
            }))
            .app_data(web::Data::new(redis.clone()))
            .app_data(fed_app_data.clone())
            .service(
                web::resource("/stuff")
                    .route(web::get().to(get_from_cache))
                    .route(web::post().to(cache_stuff)),
            )
            .service(index)
            .service(openid_federation)
            .service(list_subordinates)
            .service(fetch_subordinates)
            .service(resolve_entity)
            .service(fetch_collections)
            .service(trust_mark_query)
            .service(trust_marked_list)
            .service(trust_mark_status)
            .wrap(middleware::NormalizePath::trim())
            .wrap(middleware::Logger::default())
    })
    .workers(2)
    .bind(("0.0.0.0", port))?
    .run()
    .await
}
