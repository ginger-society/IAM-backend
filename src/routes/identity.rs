use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Utc};
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::{insert_into, PgConnection, RunQueryDsl};
use jsonwebtoken::{encode, EncodingKey, Header};
use rocket::serde::json::Json;
use rocket::{post, State};
use rocket_okapi::openapi;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::env;

use crate::models::schema::schema::token::dsl::*;
use crate::models::schema::schema::user::dsl::*;
use crate::models::schema::{Token, TokenInsertable, User, UserInsertable};

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RegisterRequest {
    email: String,
    password: String,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct LoginResponse {
    access_token: String,
    refresh_token: String,
}

#[openapi(tag = "User")]
#[post("/register", data = "<register_request>")]
pub fn register(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    register_request: Json<RegisterRequest>,
) -> Json<String> {
    let mut conn = rdb.get().expect("Failed to get DB connection");
    let hashed_password =
        hash(&register_request.password, DEFAULT_COST).expect("Failed to hash password");

    let new_user = UserInsertable {
        first_name: None,
        last_name: None,
        middle_name: None,
        email_id: register_request.email.clone(),
        mobile_number: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        password_hash: Some(hashed_password.clone()),
    };

    insert_into(user)
        .values(&new_user)
        .execute(&mut conn)
        .expect("Error inserting new user");

    Json("User registered successfully".to_string())
}

#[openapi(tag = "User")]
#[post("/login", data = "<login_request>")]
pub fn login(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    login_request: Json<LoginRequest>,
) -> Json<LoginResponse> {
    let mut conn = rdb.get().expect("Failed to get DB connection");

    let u: User = user
        .filter(email_id.eq(&login_request.email))
        .first(&mut conn)
        .expect("Error getting user");

    let valid = verify(&login_request.password, u.password_hash.as_ref().unwrap())
        .expect("Failed to verify password");

    if valid {
        let access_token = create_jwt(&u.email_id, &u.id.to_string(), "access");
        let refresh_token = create_jwt(&u.email_id, &u.id.to_string(), "refresh");

        insert_into(token)
            .values(TokenInsertable {
                session_hash: Some(refresh_token.clone()),
                user_id: u.id,
            })
            .execute(&mut conn)
            .expect("Error inserting token");

        Json(LoginResponse {
            access_token,
            refresh_token,
        })
    } else {
        Json(LoginResponse {
            access_token: "".to_string(),
            refresh_token: "".to_string(),
        })
    }
}

fn create_jwt(email: &str, uid: &str, token_type: &str) -> String {
    let expiration = match token_type {
        "access" => Utc::now() + Duration::minutes(15), // Short-lived access token
        "refresh" => Utc::now() + Duration::days(30),   // Longer-lived refresh token
        _ => panic!("Invalid token type"),
    };
    let claims = Claims {
        sub: email.to_owned(),
        exp: expiration.timestamp() as usize,
        user_id: uid.to_owned(),
        token_type: token_type.to_owned(),
    };
    let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .unwrap()
}
#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
    user_id: String,
    token_type: String, // Add token_type to distinguish between access and refresh tokens
}
