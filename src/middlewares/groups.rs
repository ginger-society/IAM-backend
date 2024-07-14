use diesel::prelude::*;
use diesel::r2d2::ConnectionManager;
use diesel::r2d2::Pool;
use diesel::{PgConnection, RunQueryDsl};
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};
use rocket::State;
use rocket_okapi::request::OpenApiFromRequest;
use rocket_okapi::request::RequestHeaderInput;
use rocket_okapi::OpenApiError;
use serde::{Deserialize, Serialize};

use super::jwt::Claims;

#[derive(Debug, Serialize, Deserialize)]
pub struct Groups(Vec<String>);

impl Groups {
    pub fn new(groups: Vec<String>) -> Self {
        Groups(groups)
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Groups {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        use crate::models::schema::schema::group::dsl::{group, id as group_id, identifier};
        use crate::models::schema::schema::group_users::dsl::{
            group_id as gu_group_id, group_users, user_id as gu_user_id,
        };

        let rdb = request
            .guard::<&State<Pool<ConnectionManager<PgConnection>>>>()
            .await;
        let claims = request.guard::<Claims>().await;

        if let (Outcome::Success(pool), Outcome::Success(claims)) = (rdb, claims) {
            let mut connection = match pool.get() {
                Ok(conn) => conn,
                Err(_) => return Outcome::Error((Status::ServiceUnavailable, ())),
            };

            let results: Vec<String> = group_users
                .inner_join(group.on(group_id.eq(gu_group_id)))
                .filter(gu_user_id.eq(claims.user_id.parse::<i64>().unwrap()))
                .select(identifier)
                .load::<String>(&mut connection)
                .unwrap_or_else(|_| vec![]);

            Outcome::Success(Groups::new(results))
        } else {
            Outcome::Error((Status::Unauthorized, ()))
        }
    }
}

// Implement OpenApiFromRequest for Groups
impl<'a> OpenApiFromRequest<'a> for Groups {
    fn from_request_input(
        _gen: &mut rocket_okapi::gen::OpenApiGenerator,
        _name: String,
        _required: bool,
    ) -> Result<RequestHeaderInput, OpenApiError> {
        Ok(RequestHeaderInput::None)
    }
}
