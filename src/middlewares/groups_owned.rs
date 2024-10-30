use diesel::prelude::*;
use diesel::r2d2::ConnectionManager;
use diesel::r2d2::Pool;
use diesel::PgConnection;
use ginger_shared_rs::rocket_utils::Claims;
use r2d2_redis::redis::Commands;
use r2d2_redis::RedisConnectionManager;
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};
use rocket::State;
use rocket_okapi::request::OpenApiFromRequest;
use rocket_okapi::request::RequestHeaderInput;
use rocket_okapi::OpenApiError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct GroupOwnerships(pub Vec<String>);

impl GroupOwnerships {
    pub fn new(groups: Vec<String>) -> Self {
        GroupOwnerships(groups)
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for GroupOwnerships {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        use crate::models::schema::schema::group::dsl::{group, id as group_id, identifier};
        use crate::models::schema::schema::group_owners::dsl::{
            group_id as gu_group_id, group_owners, user_id as gu_user_id,
        };

        let rdb = request
            .guard::<&State<Pool<ConnectionManager<PgConnection>>>>()
            .await;

        let cache = request
            .guard::<&State<Pool<RedisConnectionManager>>>()
            .await;

        let claims = request.guard::<Claims>().await;

        if let (Outcome::Success(pool), Outcome::Success(cache_pool), Outcome::Success(claims)) =
            (rdb, cache, claims)
        {
            let mut connection = match pool.get() {
                Ok(conn) => conn,
                Err(_) => return Outcome::Error((Status::ServiceUnavailable, ())),
            };

            let mut cache_connection = match cache_pool.get() {
                Ok(conn) => conn,
                Err(_) => return Outcome::Error((Status::ServiceUnavailable, ())),
            };

            let cache_key = format!("groups_owned:{}", claims.user_id);

            match cache_connection.get::<_, Option<String>>(&cache_key) {
                Ok(Some(cached_groups)) => {
                    let gs: Vec<String> = serde_json::from_str(&cached_groups).unwrap_or_default();
                    Outcome::Success(GroupOwnerships::new(gs))
                }
                Ok(None) | Err(_) => {
                    let results: Vec<String> = group_owners
                        .inner_join(group.on(group_id.eq(gu_group_id)))
                        .filter(gu_user_id.eq(claims.user_id.parse::<i64>().unwrap()))
                        .select(identifier)
                        .load::<String>(&mut connection)
                        .unwrap_or_else(|_| vec![]);

                    let groups_json = serde_json::to_string(&results).unwrap_or_default();
                    let _: () = cache_connection
                        .set_ex(&cache_key, groups_json, 3600)
                        .unwrap_or(());

                    Outcome::Success(GroupOwnerships::new(results))
                }
            }
        } else {
            Outcome::Error((Status::Unauthorized, ()))
        }
    }
}

// Implement OpenApiFromRequest for GroupOwnerships
impl<'a> OpenApiFromRequest<'a> for GroupOwnerships {
    fn from_request_input(
        _gen: &mut rocket_okapi::gen::OpenApiGenerator,
        _name: String,
        _required: bool,
    ) -> Result<RequestHeaderInput, OpenApiError> {
        Ok(RequestHeaderInput::None)
    }
}
