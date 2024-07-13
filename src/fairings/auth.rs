use rocket::{
    fairing::{Fairing, Info, Kind},
    outcome::Outcome,
    Request,
};

use crate::middlewares::jwt::Claims;

pub struct AuthFairing;

#[rocket::async_trait]
impl Fairing for AuthFairing {
    fn info(&self) -> Info {
        Info {
            name: "JWT Auth Fairing",
            kind: Kind::Request,
        }
    }

    async fn on_request(&self, request: &mut Request<'_>, _: &mut rocket::Data<'_>) {
        if let Outcome::Success(claims) = request.guard::<Claims>().await {
            request.local_cache(|| Some(claims));
        } else {
            request.local_cache(|| None::<Claims>);
        }
    }
}
