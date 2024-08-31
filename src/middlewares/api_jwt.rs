use jsonwebtoken::decode;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::Validation;
use okapi::openapi3::Object;
use okapi::openapi3::SecurityRequirement;
use okapi::openapi3::SecurityScheme;
use okapi::openapi3::SecuritySchemeData;
use rocket::serde::Deserialize;
use rocket::serde::Serialize;
use rocket_okapi::gen::OpenApiGenerator;
use rocket_okapi::request::OpenApiFromRequest;
use rocket_okapi::request::RequestHeaderInput;

use std::env;

use rocket::{
    http::Status,
    request::{FromRequest, Outcome, Request},
};

#[derive(Serialize, Deserialize)]
pub struct APIClaims {
    pub sub: String,
    pub exp: usize,
    pub group_id: i64,
    pub scopes: Vec<String>,
}

#[derive(Debug)]
pub enum APIClaimsError {
    Missing,
    Invalid,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for APIClaims {
    type Error = APIClaimsError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let keys: Vec<_> = request.headers().get("X-API-Authorization").collect();
        if keys.len() != 1 {
            return Outcome::Error((Status::Unauthorized, APIClaimsError::Missing));
        }

        let token_str = keys[0].trim_start_matches("Bearer ").trim();
        let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
        let decoding_key = DecodingKey::from_secret(secret.as_ref());

        match decode::<APIClaims>(
            token_str,
            &decoding_key,
            &Validation::new(jsonwebtoken::Algorithm::HS256),
        ) {
            Ok(token_data) => Outcome::Success(token_data.claims),
            Err(_) => Outcome::Error((Status::Unauthorized, APIClaimsError::Invalid)),
        }
    }
}

impl<'a> OpenApiFromRequest<'a> for APIClaims {
    fn from_request_input(
        _gen: &mut OpenApiGenerator,
        _name: String,
        _required: bool,
    ) -> rocket_okapi::Result<RequestHeaderInput> {
        let security_scheme = SecurityScheme {
            description: Some("Requires a Bearer token to access".to_owned()),
            data: SecuritySchemeData::ApiKey {
                name: "X-API-Authorization".to_owned(),
                location: "header".to_owned(),
            },
            extensions: Object::default(),
        };

        let mut security_req = SecurityRequirement::new();
        security_req.insert("BearerAuth".to_owned(), Vec::new());

        Ok(RequestHeaderInput::Security(
            "BearerAPIAuth".to_owned(),
            security_scheme,
            security_req,
        ))
    }

    fn get_responses(
        _gen: &mut rocket_okapi::gen::OpenApiGenerator,
    ) -> rocket_okapi::Result<okapi::openapi3::Responses> {
        Ok(okapi::openapi3::Responses::default())
    }
}
