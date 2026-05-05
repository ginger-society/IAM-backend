use std::env;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};
use rocket_okapi::request::OpenApiFromRequest;
use rocket_okapi::request::RequestHeaderInput;
use rocket_okapi::OpenApiError;
use ginger_shared_rs::rocket_utils::{APIClaims, Claims};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct BasicAuth {
    pub subject: String,
}

impl BasicAuth {
    pub fn new(subject: String) -> Self {
        BasicAuth { subject }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for BasicAuth {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let secret = match env::var("JWT_SECRET") {
            Ok(s) => s,
            Err(_) => return Outcome::Error((Status::InternalServerError, ())),
        };

        let auth_header = request.headers().get_one("Authorization");

        match auth_header {
            Some(header) if header.starts_with("Basic ") => {
                let encoded = &header["Basic ".len()..];

                let decoded = match BASE64_STANDARD.decode(encoded) {
                    Ok(b) => match String::from_utf8(b) {
                        Ok(s) => s,
                        Err(_) => return Outcome::Error((Status::Unauthorized, ())),
                    },
                    Err(_) => return Outcome::Error((Status::Unauthorized, ())),
                };

                let mut parts = decoded.splitn(2, ':');
                let _username = parts.next().unwrap_or("");
                let password = match parts.next() {
                    Some(p) => p.to_string(),
                    None => return Outcome::Error((Status::Unauthorized, ())),
                };

                let decoding_key = DecodingKey::from_secret(secret.as_ref());
                let validation = Validation::new(Algorithm::HS256);

                // Try as Claims (user JWT) first
                if let Ok(token_data) = decode::<Claims>(&password, &decoding_key, &validation) {
                    return Outcome::Success(BasicAuth::new(token_data.claims.sub));
                }

                // Try as APIClaims (API JWT)
                if let Ok(token_data) = decode::<APIClaims>(&password, &decoding_key, &validation) {
                    return Outcome::Success(BasicAuth::new(token_data.claims.sub));
                }

                // Neither worked
                Outcome::Error((Status::Unauthorized, ()))
            }

            // No auth header — anonymous access for public pulls
            None => Outcome::Success(BasicAuth::new("".to_string())),

            _ => Outcome::Error((Status::Unauthorized, ())),
        }
    }
}

impl<'a> OpenApiFromRequest<'a> for BasicAuth {
    fn from_request_input(
        _gen: &mut rocket_okapi::gen::OpenApiGenerator,
        _name: String,
        _required: bool,
    ) -> Result<RequestHeaderInput, OpenApiError> {
        Ok(RequestHeaderInput::None)
    }
}