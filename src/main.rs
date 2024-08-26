#[macro_use]
extern crate rocket;
use fairings::auth::AuthFairing;
use rocket::Rocket;

use crate::routes::identity;
use db::redis::create_redis_pool;
use dotenv::dotenv;
use rocket::Build;
use rocket_okapi::openapi_get_routes;
use rocket_okapi::swagger_ui::{make_swagger_ui, SwaggerUIConfig};
use rocket_prometheus::PrometheusMetrics;
use std::env;
mod db;
mod errors;
mod fairings;
mod middlewares;
mod models;
mod routes;

#[launch]
fn rocket() -> Rocket<Build> {
    dotenv().ok();
    let prometheus = PrometheusMetrics::new();

    let mut server = rocket::build()
        .manage(db::connect_rdb())
        .attach(fairings::cors::CORS)
        .attach(prometheus.clone())
        .attach(AuthFairing)
        .mount(
            "/iam/",
            openapi_get_routes![
                routes::index,
                identity::register,
                identity::login,
                identity::refresh_token,
                identity::validate_token,
                identity::change_password,
                identity::update_profile,
                identity::get_app_by_client_id,
                identity::get_group_memberships,
                identity::create_group,
                identity::request_password_reset,
                identity::reset_password,
                identity::create_api_token,
                identity::logout,
                identity::get_group_ownserships,
                identity::get_members,
                identity::manage_membership,
                identity::create_api_session_token,
                identity::get_api_tokens_by_group,
                identity::deactivate_api_token
            ],
        )
        .mount(
            "/iam/api-docs",
            make_swagger_ui(&SwaggerUIConfig {
                url: "../openapi.json".to_owned(),
                ..Default::default()
            }),
        )
        .mount("/iam/metrics", prometheus);

    match env::var("MONGO_URI") {
        Ok(mongo_uri) => match env::var("MONGO_DB_NAME") {
            Ok(mongo_db_name) => {
                println!("Attempting to connect to mongo");
                server = server.manage(db::connect_mongo(mongo_uri, mongo_db_name))
            }
            Err(_) => {
                println!("Not connecting to mongo, missing MONGO_DB_NAME")
            }
        },
        Err(_) => println!("Not connecting to mongo, missing MONGO_URI"),
    };

    match env::var("REDIS_URI") {
        Ok(redis_uri) => {
            println!("Attempting to connect to redis");
            server = server.manage(create_redis_pool(redis_uri))
        }
        Err(_) => println!("Not connecting to redis"),
    }

    server
}

// Unit testings
#[cfg(test)]
mod tests;
