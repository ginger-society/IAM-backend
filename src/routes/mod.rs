use crate::models::response::MessageResponse;
use diesel::r2d2;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::PgConnection;
use r2d2_redis::RedisConnectionManager;
use rocket::serde::json::Json;
use rocket::State;
use rocket_okapi::openapi;

pub mod identity;

/// This is a description. <br />You can do simple html <br /> like <b>this<b/>
#[openapi(tag = "Healthcheck")]
#[get("/")]
pub fn index(
    rdb: &State<r2d2::Pool<ConnectionManager<PgConnection>>>,
    cache: &State<Pool<RedisConnectionManager>>,
) -> Json<MessageResponse> {
    Json(MessageResponse {
        message: "Ok".to_string(),
    })
}
