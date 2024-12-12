use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Utc};
use diesel::pg::Pg;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::sql_types::Bool;
use diesel::{insert_into, PgConnection, RunQueryDsl};
use diesel::{prelude::*, update};
use ginger_shared_rs::rocket_models::MessageResponse;
use ginger_shared_rs::rocket_utils::{APIClaims, Claims};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use r2d2_redis::redis::Commands;
use r2d2_redis::RedisConnectionManager;
use rand::Rng;
use rocket::http::Status;
use rocket::response::status;
use rocket::serde::json::Json;
use rocket::{post, State};
use rocket_okapi::openapi;
use serde_json::{json, Value};
use std::env;
use NotificationService::apis::default_api::{send_email, SendEmailParams};
use NotificationService::get_configuration as get_notification_service_configuration;

use NotificationService::apis::configuration::ApiKey as NotificationApiKey;

use crate::middlewares::groups::GroupMemberships;
use crate::middlewares::groups_owned::GroupOwnerships;
use crate::models::request::RegisterRequestValue;
use crate::models::request::{
    ChangePasswordRequest, CreateApiTokenRequest, CreateGroupRequest, CreateSessionTokenRequest,
    LoginRequest, LogoutRequest, RefreshTokenRequest, RegisterRequest, RequestPasswordRequest,
    ResetPasswordRequest, UpdateProfileRequest,
};
use crate::models::response::{
    AppResponse, CreateApiTokenResponse, CreateSessionTokenResponse, GroupApiTokenResponse,
    LoginResponse, RefreshTokenResponse, UserInfoResponse, ValidateAPITokenResponse,
    ValidateTokenResponse,
};
use crate::models::schema::{
    Api_Token, Api_TokenInsertable, App, Group, GroupInsertable, Group_OwnersInsertable,
    Group_UsersInsertable, TokenInsertable, User, UserInsertable,
};
use rand::distributions::Alphanumeric;
use NotificationService::models::EmailRequest;

#[openapi()]
#[post("/change-password", data = "<change_password_request>")]
pub fn change_password(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    change_password_request: Json<ChangePasswordRequest>,
) -> status::Custom<Json<MessageResponse>> {
    use crate::models::schema::schema::user::dsl::*;

    let mut conn = rdb.get().expect("Failed to get DB connection");

    let u: User = match user
        .filter(email_id.eq(&change_password_request.email))
        .first(&mut conn)
    {
        Ok(u) => u,
        Err(_) => {
            return status::Custom(
                Status::NotFound,
                Json(MessageResponse {
                    message: "User not found".to_string(),
                }),
            )
        }
    };

    let valid = verify(
        &change_password_request.current_password,
        u.password_hash.as_ref().unwrap(),
    )
    .expect("Failed to verify password");

    if !valid {
        return status::Custom(
            Status::Unauthorized,
            Json(MessageResponse {
                message: "Current password is incorrect".to_string(),
            }),
        );
    }

    let new_hashed_password =
        hash(&change_password_request.new_password, DEFAULT_COST).expect("Failed to hash password");

    let updated_rows = update(user.filter(email_id.eq(&change_password_request.email)))
        .set(password_hash.eq(Some(new_hashed_password)))
        .execute(&mut conn)
        .expect("Error updating password");

    if updated_rows > 0 {
        status::Custom(
            Status::Ok,
            Json(MessageResponse {
                message: "Password updated successfully".to_string(),
            }),
        )
    } else {
        status::Custom(
            Status::InternalServerError,
            Json(MessageResponse {
                message: "Failed to update password".to_string(),
            }),
        )
    }
}

#[openapi()]
#[post("/register", data = "<register_request>")]
pub async fn register(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    cache: &State<Pool<RedisConnectionManager>>,
    register_request: Json<RegisterRequest>,
) -> Result<Json<String>, Status> {
    use crate::models::schema::schema::user::dsl::*;

    let mut conn = rdb.get().expect("Failed to get DB connection");

    let mut cache_connection = cache
        .get()
        .map_err(|_| rocket::http::Status::ServiceUnavailable)?;

    // Check if the user with the same email already exists
    let existing_user = user
        .filter(email_id.eq(&register_request.email))
        .first::<User>(&mut conn)
        .optional()
        .map_err(|_| Status::InternalServerError)?;

    if let Some(_) = existing_user {
        return Err(Status::Conflict);
    }

    let hashed_password =
        hash(&register_request.password, DEFAULT_COST).expect("Failed to hash password");

    // Generate a random hash value
    let registration_token_value: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .map(char::from)
        .collect();

    let registration_cache_value = RegisterRequestValue {
        email: register_request.email.clone(),
        hashed_password: hashed_password,
    };

    // Insert the user registration data into the cache
    let _: () = cache_connection
        .set_ex(
            &registration_token_value,
            serde_json::to_string(&registration_cache_value).unwrap(),
            300,
        ) // Token expires in 1 hour
        .map_err(|_| rocket::http::Status::InternalServerError)?;

    let mut configuration = get_notification_service_configuration();

    let token_str = env::var("ISC_SECRET").expect("ISC_SECRET must be set");

    configuration.api_key = Some(NotificationApiKey {
        key: token_str,
        prefix: None,
    });

    match send_email(
            &configuration,
            SendEmailParams {
                email_request: EmailRequest {
                    to: register_request.email.clone(),
                    subject: "Confirm Registration".to_string(),
                    message: format!("Use this link (expires within 5 minutes) to confirm your registration: https://iam-staging.gingersociety.org/#/{}/registration-confirmation/{}", register_request.app_id, registration_token_value),
                    reply_to: None,
                },
            },
        ).await{
            Ok(_) => {
                Ok(Json(
                    "User registration request generated successfully".to_string(),
                ))
            }Err(_) => {
                Err(Status::ServiceUnavailable)
            }
        }
}

#[openapi()]
#[get("/confirm-register/<registration_token>")]
pub fn registeration_confirmation(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    cache: &State<Pool<RedisConnectionManager>>,
    registration_token: String,
) -> Result<Json<String>, Status> {
    use crate::models::schema::schema::user::dsl::*;

    let mut conn = rdb.get().expect("Failed to get DB connection");

    let mut cache_connection = cache
        .get()
        .map_err(|_| rocket::http::Status::ServiceUnavailable)?;

    // Get user ID from cache using the token
    let user_data: String = cache_connection
        .get(&registration_token)
        .map_err(|_| rocket::http::Status::NotFound)?;

    // Remove the token from cache after reading
    cache_connection
        .del(&registration_token)
        .map_err(|_| Status::InternalServerError)?;

    let register_request: RegisterRequestValue = serde_json::from_str(&user_data).unwrap();

    let new_user = UserInsertable {
        first_name: None,
        last_name: None,
        middle_name: None,
        email_id: register_request.email,
        mobile_number: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        password_hash: Some(register_request.hashed_password),
        is_root: false,
    };

    insert_into(user)
        .values(&new_user)
        .execute(&mut conn)
        .expect("Error inserting new user");

    Ok(Json("User registered successfully".to_string()))
}
#[openapi()]
#[post("/login", data = "<login_request>")]
pub fn login(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    login_request: Json<LoginRequest>,
    cache_pool: &State<Pool<RedisConnectionManager>>,
) -> Result<Json<LoginResponse>, rocket::http::Status> {
    use crate::models::schema::schema::app::dsl::*;
    use crate::models::schema::schema::user::dsl::*;

    let mut conn = rdb
        .get()
        .map_err(|_| rocket::http::Status::ServiceUnavailable)?;

    let mut cache_connection = cache_pool
        .get()
        .map_err(|_| rocket::http::Status::ServiceUnavailable)?;

    // Fetch the user by email
    let u: User = user
        .filter(email_id.eq(&login_request.email))
        .first(&mut conn)
        .map_err(|_| rocket::http::Status::Unauthorized)?;

    // Verify the password
    let valid = verify(&login_request.password, u.password_hash.as_ref().unwrap())
        .map_err(|_| rocket::http::Status::Unauthorized)?;

    if valid {
        // Create JWT tokens
        let access_token = create_jwt(
            &u.email_id,
            &u.id.to_string(),
            "access",
            &u.first_name,
            &u.last_name,
            &u.middle_name,
            &login_request.client_id,
        );
        let refresh_token = create_jwt(
            &u.email_id,
            &u.id.to_string(),
            "refresh",
            &u.first_name,
            &u.last_name,
            &u.middle_name,
            &login_request.client_id,
        );

        // Fetch the app using client_id
        let a: App = app
            .filter(client_id.eq(&login_request.client_id))
            .first(&mut conn)
            .map_err(|_| rocket::http::Status::Unauthorized)?;

        // Store session data as JSON in Redis
        let session_data = json!({
            "user_id": u.id,
            "app_id": a.id,
        });
        let _: () = cache_connection
            .set_ex(refresh_token.clone(), session_data.to_string(), 3600) // Token expires in 1 hour
            .map_err(|_| rocket::http::Status::InternalServerError)?;

        // Return tokens in the response
        Ok(Json(LoginResponse {
            access_token,
            refresh_token,
        }))
    } else {
        // Respond with Unauthorized status if password is invalid
        Err(rocket::http::Status::Unauthorized)
    }
}
#[openapi()]
#[post("/refresh-token", data = "<refresh_request>")]
pub fn refresh_token(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    refresh_request: Json<RefreshTokenRequest>,
    cache_pool: &State<Pool<RedisConnectionManager>>,
) -> Result<Json<RefreshTokenResponse>, rocket::http::Status> {
    let mut cache_connection = cache_pool
        .get()
        .map_err(|_| rocket::http::Status::ServiceUnavailable)?;

    // Decode the refresh token
    let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let decoding_key = DecodingKey::from_secret(secret.as_ref());

    let token_data = decode::<Claims>(
        &refresh_request.refresh_token,
        &decoding_key,
        &Validation::new(Algorithm::HS256),
    )
    .map_err(|_| rocket::http::Status::Unauthorized)?;

    // Verify the token type
    if token_data.claims.token_type != "refresh" {
        return Err(rocket::http::Status::Unauthorized);
    }

    // Verify if the refresh token exists in Redis
    let refresh_token_exists: bool = cache_connection
        .exists(&refresh_request.refresh_token)
        .map_err(|_| rocket::http::Status::ServiceUnavailable)?;

    if !refresh_token_exists {
        return Err(rocket::http::Status::Unauthorized);
    }

    // Generate a new access token
    let access_token = create_jwt(
        &token_data.claims.sub,
        &token_data.claims.user_id,
        "access",
        &token_data.claims.first_name,
        &token_data.claims.last_name,
        &token_data.claims.middle_name,
        &token_data.claims.client_id,
    );

    Ok(Json(RefreshTokenResponse { access_token }))
}

#[openapi()]
#[get("/validate")]
pub fn validate_token(claims: Claims) -> Result<Json<ValidateTokenResponse>, rocket::http::Status> {
    Ok(Json(ValidateTokenResponse {
        sub: claims.sub,
        exp: claims.exp,
        user_id: claims.user_id,
        first_name: claims.first_name,
        last_name: claims.last_name,
        middle_name: claims.middle_name,
        client_id: claims.client_id,
    }))
}

#[openapi()]
#[get("/validate-api-token")]
pub fn validate_api_token(
    claims: APIClaims,
) -> Result<Json<ValidateAPITokenResponse>, rocket::http::Status> {
    Ok(Json(ValidateAPITokenResponse {
        sub: claims.sub,
        exp: claims.exp,
        group_id: claims.group_id,
        scopes: claims.scopes,
    }))
}

fn create_jwt(
    email: &str,
    uid: &str,
    token_type: &str,
    f_name: &Option<String>,
    l_name: &Option<String>,
    m_name: &Option<String>,
    c_id: &String,
) -> String {
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
        first_name: f_name.clone(),
        last_name: l_name.clone(),
        middle_name: m_name.clone(),
        client_id: c_id.clone(),
    };
    let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .unwrap()
}

#[openapi()]
#[put("/update-profile", data = "<update_request>")]
pub fn update_profile(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    claims: Claims,
    update_request: Json<UpdateProfileRequest>,
) -> Result<Json<MessageResponse>, Status> {
    let mut conn: diesel::r2d2::PooledConnection<ConnectionManager<PgConnection>> =
        rdb.get().map_err(|_| Status::ServiceUnavailable)?;

    use crate::models::schema::schema::user::dsl::*;

    let user_id = claims.user_id.parse::<i64>().unwrap();

    let updated_rows = diesel::update(user.filter(id.eq(user_id)))
        .set((
            first_name.eq(&update_request.first_name),
            middle_name.eq(&update_request.middle_name),
            last_name.eq(&update_request.last_name),
            mobile_number.eq(&update_request.mobile_number),
        ))
        .execute(&mut conn)
        .map_err(|_| Status::InternalServerError)?;

    if updated_rows > 0 {
        Ok(Json(MessageResponse {
            message: "Profile updated successfully".to_string(),
        }))
    } else {
        Err(Status::NotFound)
    }
}

#[openapi]
#[get("/app-details/<client_id_>")]
pub fn get_app_by_client_id(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    client_id_: String,
) -> Result<Json<AppResponse>, rocket::http::Status> {
    use crate::models::schema::schema::app::dsl::*;

    let mut conn = rdb
        .get()
        .map_err(|_| rocket::http::Status::InternalServerError)?;

    match app
        .filter(client_id.eq(&client_id_))
        .filter(disabled.eq(false))
        .first::<App>(&mut conn)
    {
        Ok(a) => Ok(Json(AppResponse {
            name: a.name,
            logo_url: a.logo_url,
            app_url_dev: a.app_url_dev,
            app_url_stage: a.app_url_stage,
            app_url_prod: a.app_url_prod,
            tnc_link: a.tnc_link,
            allow_registration: a.allow_registration,
        })),
        Err(_) => Err(rocket::http::Status::NotFound),
    }
}

#[openapi]
#[get("/group-ownerships")]
pub fn get_group_memberships(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    claims: Claims,
    groups: GroupMemberships,
) -> Result<Json<Vec<String>>, rocket::http::Status> {
    Ok(Json(groups.0))
}

#[openapi]
#[get("/group-memberships")]
pub fn get_group_ownserships(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    claims: Claims,
    groups_owned: GroupOwnerships,
) -> Result<Json<Vec<String>>, rocket::http::Status> {
    Ok(Json(groups_owned.0))
}

#[openapi]
#[get("/clear-redis")]
pub fn clear_redis(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    claims: Claims,
    cache_pool: &State<Pool<RedisConnectionManager>>,
) -> Result<Json<String>, rocket::http::Status> {
    // Attempt to get a connection from the Redis pool
    let mut cache_connection = cache_pool
        .get()
        .map_err(|_| rocket::http::Status::ServiceUnavailable)?;

    // Create cache keys using the user's ID from claims
    let cache_key = format!("user_groups:{}", claims.user_id);
    let cache_key_2 = format!("groups_owned:{}", claims.user_id);

    // Attempt to delete the first cache key
    cache_connection
        .del::<_, i32>(&cache_key)
        .map_err(|_| rocket::http::Status::InternalServerError)?;

    // Attempt to delete the second cache key
    cache_connection
        .del::<_, i32>(&cache_key_2)
        .map_err(|_| rocket::http::Status::InternalServerError)?;

    // Return success message
    Ok(Json("Successfully cleared Redis cache.".to_string()))
}

#[openapi()]
#[post("/create-group", data = "<create_request>")]
pub fn create_group(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    claims: Claims,
    create_request: Json<CreateGroupRequest>,
    cache_pool: &State<Pool<RedisConnectionManager>>,
) -> Result<Json<Group>, status::Custom<String>> {
    use crate::models::schema::schema::group::dsl::*;
    use crate::models::schema::schema::group_owners::dsl::*;
    use crate::models::schema::schema::group_users::dsl::*;

    // Attempt to get a database connection
    let mut conn = rdb.get().map_err(|_| {
        status::Custom(
            rocket::http::Status::ServiceUnavailable,
            "Database connection is unavailable.".to_string(),
        )
    })?;

    // Attempt to get a cache connection
    let mut cache_connection = cache_pool.get().map_err(|_| {
        status::Custom(
            rocket::http::Status::ServiceUnavailable,
            "Cache connection is unavailable.".to_string(),
        )
    })?;

    // Check if the group already exists
    let group_exists = group
        .filter(identifier.eq(&create_request.id))
        .first::<Group>(&mut conn)
        .optional()
        .map_err(|_| {
            status::Custom(
                rocket::http::Status::InternalServerError,
                "Error checking if the group already exists.".to_string(),
            )
        })?;

    // If the group already exists, return a conflict status
    if group_exists.is_some() {
        return Err(status::Custom(
            rocket::http::Status::Conflict,
            "A group with this identifier already exists.".to_string(),
        ));
    }

    // Attempt to insert the new group
    let new_group = GroupInsertable {
        identifier: create_request.id.clone(),
        disabled: false,
        short_text: create_request.description.clone(),
    };

    let created_group = diesel::insert_into(group)
        .values(&new_group)
        .get_result::<Group>(&mut conn)
        .map_err(|_| {
            status::Custom(
                rocket::http::Status::InternalServerError,
                "Error creating the new group.".to_string(),
            )
        })?;

    // Attempt to insert into group_users
    let new_group_user = Group_UsersInsertable {
        user_id: claims.user_id.parse::<i64>().unwrap(),
        group_id: created_group.id,
    };

    diesel::insert_into(group_users)
        .values(&new_group_user)
        .execute(&mut conn)
        .map_err(|_| {
            status::Custom(
                rocket::http::Status::InternalServerError,
                "Error adding the user to the group.".to_string(),
            )
        })?;

    // Attempt to insert into group_owners
    let new_group_owner = Group_OwnersInsertable {
        user_id: claims.user_id.parse::<i64>().unwrap(),
        group_id: created_group.id,
    };

    diesel::insert_into(group_owners)
        .values(&new_group_owner)
        .execute(&mut conn)
        .map_err(|_| {
            status::Custom(
                rocket::http::Status::InternalServerError,
                "Error adding the user as a group owner.".to_string(),
            )
        })?;

    // Attempt to delete the user's cached groups
    let cache_key = format!("user_groups:{}", claims.user_id);

    let _ = cache_connection.del::<_, i32>(&cache_key).map_err(|_| {
        status::Custom(
            rocket::http::Status::InternalServerError,
            "Error clearing the user's cached group list.".to_string(),
        )
    })?;

    // If everything is successful, return the created group
    Ok(Json(created_group))
}

#[openapi()]
#[post("/request-password", data = "<request>")]
pub async fn request_password_reset(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    cache: &State<Pool<RedisConnectionManager>>,
    request: Json<RequestPasswordRequest>,
) -> Result<Json<MessageResponse>, rocket::http::Status> {
    use crate::models::schema::schema::user::dsl::*;

    let mut cache_connection = cache
        .get()
        .map_err(|_| rocket::http::Status::ServiceUnavailable)?;

    let mut conn = rdb
        .get()
        .map_err(|_| rocket::http::Status::ServiceUnavailable)?;

    // Find the user by email
    let u = user
        .filter(email_id.eq(&request.email_id))
        .first::<User>(&mut conn)
        .map_err(|_| rocket::http::Status::NotFound)?;

    // Generate a random hash value
    let token_value: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .map(char::from)
        .collect();
    println!("{:?}", token_value);
    // Insert the token into the database
    let _: () = cache_connection
        .set_ex(&token_value, u.id, 300) // Token expires in 5 minutes
        .map_err(|_| rocket::http::Status::InternalServerError)?;

    let mut configuration = get_notification_service_configuration();

    let token_str = env::var("ISC_SECRET").expect("ISC_SECRET must be set");

    configuration.api_key = Some(NotificationApiKey {
        key: token_str,
        prefix: None,
    });

    match send_email(
        &configuration,
        SendEmailParams {
            email_request: EmailRequest {
                to: request.email_id.clone(),
                subject: "Password Reset".to_string(),
                message: format!("Use this link(expires within 5 minutes) to reset your password: https://iam-staging.gingersociety.org/#/{}/reset-password/{}", request.app_id, token_value),
                reply_to: None,
            },
        },
    )
    .await
    {
        Ok(_) => Ok(Json(MessageResponse {
            message: "Password reset token created successfully".to_string(),
        })),
        Err(_) => Err(Status::ServiceUnavailable),
    }
}

#[openapi()]
#[post("/reset-password", data = "<request>")]
pub fn reset_password(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    cache: &State<Pool<RedisConnectionManager>>,
    request: Json<ResetPasswordRequest>,
) -> Result<Json<MessageResponse>, rocket::http::Status> {
    use crate::models::schema::schema::user::dsl::*;

    let mut cache_connection = cache
        .get()
        .map_err(|_| rocket::http::Status::ServiceUnavailable)?;

    let mut conn = rdb
        .get()
        .map_err(|_| rocket::http::Status::ServiceUnavailable)?;

    // Get user ID from cache using the token
    let user_id: i64 = cache_connection
        .get(&request.token)
        .map_err(|_| rocket::http::Status::NotFound)?;

    // Hash the new password
    let new_hashed_password = hash(&request.new_password, DEFAULT_COST)
        .map_err(|_| rocket::http::Status::InternalServerError)?;

    // Update the user's password in the database
    let updated_rows = update(user.filter(id.eq(user_id)))
        .set(password_hash.eq(Some(new_hashed_password)))
        .execute(&mut conn)
        .map_err(|_| rocket::http::Status::InternalServerError)?;

    if updated_rows > 0 {
        // Delete the token from cache
        let _: () = cache_connection
            .del(&request.token)
            .map_err(|_| rocket::http::Status::InternalServerError)?;

        Ok(Json(MessageResponse {
            message: "Password updated successfully".to_string(),
        }))
    } else {
        Err(rocket::http::Status::InternalServerError)
    }
}

#[openapi]
#[post("/create-api-token", data = "<create_request>")]
pub fn create_api_token(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    create_request: Json<CreateApiTokenRequest>,
    claims: Claims,
) -> status::Custom<Json<CreateApiTokenResponse>> {
    use crate::models::schema::schema::api_token::dsl::*;
    use crate::models::schema::schema::group::dsl as group_dsl;

    let mut conn = rdb.get().expect("Failed to get DB connection");

    // Extract information from claims
    let user_id = claims.user_id;
    let first_name = claims.first_name;
    let last_name = claims.last_name;
    let middle_name = claims.middle_name;
    let client_id = claims.client_id;
    let email = claims.sub;

    // Generate a JWT token
    let expiration = Utc::now() + Duration::days(create_request.days_to_expire);
    let new_claims = Claims {
        sub: email,
        exp: expiration.timestamp() as usize,
        user_id,
        token_type: "api".to_string(),
        first_name,
        last_name,
        middle_name,
        client_id,
    };

    let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let token = encode(
        &Header::default(),
        &new_claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .expect("Failed to create token");

    // Find the group by its identifier
    let group: Group = group_dsl::group
        .filter(group_dsl::identifier.eq(&create_request.group_identifier))
        .first::<Group>(&mut conn)
        .map_err(|_| Status::NotFound)
        .unwrap();

    // Insert the new API token into the database
    let new_token = Api_TokenInsertable {
        parent_id: group.id,
        expiry_date: expiration.naive_utc().date(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        is_active: true, // Assuming token is active by default
        name: create_request.name.clone(),
        token_str: Some(token.clone()),
    };

    diesel::insert_into(api_token)
        .values(&new_token)
        .execute(&mut conn)
        .expect("Failed to insert new API token");

    // Return the generated token
    status::Custom(
        Status::Ok,
        Json(CreateApiTokenResponse { api_token: token }),
    )
}

#[openapi()]
#[post("/logout", data = "<logout_request>")]
pub fn logout(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    cache: &State<Pool<RedisConnectionManager>>,
    logout_request: Json<LogoutRequest>,
    claims: Claims,
) -> Result<Json<MessageResponse>, rocket::http::Status> {
    use crate::models::schema::schema::token::dsl::*;

    let mut conn = rdb
        .get()
        .map_err(|_| rocket::http::Status::ServiceUnavailable)?;

    let mut cache_connection = cache
        .get()
        .map_err(|_| rocket::http::Status::ServiceUnavailable)?;

    // Verify if the refresh token exists in the database
    let refresh_token_exists: bool = token
        .filter(session_hash.eq(&logout_request.refresh_token))
        .filter(user_id.eq(claims.user_id.parse::<i64>().unwrap()))
        .execute(&mut conn)
        .is_ok();

    if !refresh_token_exists {
        return Err(rocket::http::Status::Unauthorized);
    }

    // Delete the refresh token from the database
    diesel::delete(token.filter(session_hash.eq(&logout_request.refresh_token)))
        .execute(&mut conn)
        .map_err(|_| rocket::http::Status::InternalServerError)?;

    // Clear the Redis cache related to the user session
    let cache_key = format!("user_session:{}", claims.user_id);
    let _: () = cache_connection
        .del(&cache_key)
        .map_err(|_| rocket::http::Status::InternalServerError)?;

    Ok(Json(MessageResponse {
        message: "Logged out successfully".to_string(),
    }))
}

#[openapi()]
#[get("/get_members/<group_param>")]
pub fn get_members(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    group_param: String,
) -> Result<Json<Vec<UserInfoResponse>>, Status> {
    use crate::models::schema::schema::group::dsl as group_dsl;
    use crate::models::schema::schema::group_owners::dsl as group_owners_dsl;
    use crate::models::schema::schema::group_users::dsl as group_users_dsl;
    use crate::models::schema::schema::user::dsl as users_dsl;

    let mut conn = rdb.get().map_err(|_| Status::ServiceUnavailable)?;

    // Determine if `group_param` is an ID or an identifier
    let group_query: Box<dyn BoxableExpression<group_dsl::group, Pg, SqlType = Bool>> =
        if let Ok(group_id) = group_param.parse::<i64>() {
            Box::new(group_dsl::id.eq(group_id))
        } else {
            Box::new(group_dsl::identifier.eq(group_param))
        };

    // Fetch the group ID using the dynamic query
    let group_id = group_dsl::group
        .filter(group_query)
        .select(group_dsl::id)
        .first::<i64>(&mut conn)
        .optional()
        .map_err(|_| Status::InternalServerError)?
        .ok_or(Status::NotFound)?;

    // Fetch the users associated with the group
    let users = group_users_dsl::group_users
        .inner_join(users_dsl::user.on(users_dsl::id.eq(group_users_dsl::user_id)))
        .filter(group_users_dsl::group_id.eq(group_id))
        .select((
            users_dsl::first_name.nullable(),
            users_dsl::last_name.nullable(),
            users_dsl::middle_name.nullable(),
            users_dsl::email_id,
            users_dsl::id,
        ))
        .load::<(Option<String>, Option<String>, Option<String>, String, i64)>(&mut conn)
        .map_err(|_| Status::InternalServerError)?;

    // Fetch the group owners
    let group_owners: Vec<i64> = group_owners_dsl::group_owners
        .filter(group_owners_dsl::group_id.eq(group_id))
        .select(group_owners_dsl::user_id)
        .load(&mut conn)
        .map_err(|_| Status::InternalServerError)?;

    // Map the user information into the UserInfo struct
    let user_info: Vec<UserInfoResponse> = users
        .into_iter()
        .map(
            |(first_name, last_name, middle_name, email_id, pk)| UserInfoResponse {
                first_name: first_name.unwrap_or_default(),
                last_name: last_name.unwrap_or_default(),
                middle_name,
                pk,
                is_admin: group_owners.contains(&pk),
                email_id,
            },
        )
        .collect();

    Ok(Json(user_info))
}

fn fetch_group_members_ids(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    group_identifier: &str,
) -> Result<Vec<i64>, Status> {
    use crate::models::schema::schema::group::dsl as group_dsl;
    use crate::models::schema::schema::group_users::dsl as group_users_dsl;
    let mut conn = rdb.get().map_err(|_| Status::ServiceUnavailable)?;

    // Fetch the group ID based on the identifier
    let group_id = group_dsl::group
        .filter(group_dsl::identifier.eq(group_identifier))
        .select(group_dsl::id)
        .first::<i64>(&mut conn)
        .optional()
        .map_err(|_| Status::InternalServerError)?
        .ok_or(Status::NotFound)?;

    // Fetch the user IDs associated with the group
    let user_ids = group_users_dsl::group_users
        .filter(group_users_dsl::group_id.eq(group_id))
        .select(group_users_dsl::user_id)
        .load::<i64>(&mut conn)
        .map_err(|_| Status::InternalServerError)?;

    Ok(user_ids)
}

#[openapi()]
#[get("/get_group_members_ids/<group_identifier>")]
pub fn get_group_members_ids(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    group_identifier: String,
    _claims: APIClaims,
) -> Result<Json<Vec<i64>>, Status> {
    let user_ids = fetch_group_members_ids(rdb, &group_identifier)?;
    Ok(Json(user_ids))
}

#[openapi()]
#[get("/user-land/get_group_members_ids/<group_identifier>")]
pub fn get_group_members_ids_user_land(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    group_identifier: String,
    _claims: Claims,
) -> Result<Json<Vec<i64>>, Status> {
    let user_ids = fetch_group_members_ids(rdb, &group_identifier)?;
    Ok(Json(user_ids))
}

#[openapi()]
#[put("/manage-membership/<group_param>/<user_id>/<action>")]
pub fn manage_membership(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    group_param: String,
    user_id: String,
    action: String,
) -> Result<Json<Value>, Status> {
    let mut conn = rdb.get().map_err(|_| Status::ServiceUnavailable)?;

    use crate::models::schema::schema::group::dsl as group_dsl;
    use crate::models::schema::schema::group_owners::dsl as group_owners_dsl;
    use crate::models::schema::schema::group_users::dsl as group_users_dsl;
    use crate::models::schema::schema::user::dsl as user_dsl;

    let group_query: Box<dyn BoxableExpression<group_dsl::group, Pg, SqlType = Bool>> =
        if let Ok(group_id) = group_param.parse::<i64>() {
            Box::new(group_dsl::id.eq(group_id))
        } else {
            Box::new(group_dsl::identifier.eq(group_param))
        };
    // Find the group by its identifier
    let group: Group = group_dsl::group
        .filter(group_query)
        .first::<Group>(&mut conn)
        .map_err(|_| Status::NotFound)?;

    let user: User = user_dsl::user
        .filter(user_dsl::email_id.eq(&user_id))
        .first::<User>(&mut conn)
        .map_err(|_| Status::NotFound)?;

    match action.as_str() {
        "add-member" => {
            // Remove the user from owners
            diesel::delete(
                group_owners_dsl::group_owners
                    .filter(group_owners_dsl::user_id.eq(user.id))
                    .filter(group_owners_dsl::group_id.eq(group.id)),
            )
            .execute(&mut conn)
            .map_err(|_| Status::InternalServerError)?;

            // Add the user as a member
            diesel::insert_into(group_users_dsl::group_users)
                .values((
                    group_users_dsl::user_id.eq(user.id),
                    group_users_dsl::group_id.eq(group.id),
                ))
                .execute(&mut conn)
                .map_err(|_| Status::InternalServerError)?;
        }
        "add-admin" => {
            // Add the user as a member
            diesel::insert_into(group_users_dsl::group_users)
                .values((
                    group_users_dsl::user_id.eq(user.id),
                    group_users_dsl::group_id.eq(group.id),
                ))
                .execute(&mut conn)
                .map_err(|_| Status::InternalServerError)?;

            // Add the user as an owner
            diesel::insert_into(group_owners_dsl::group_owners)
                .values((
                    group_owners_dsl::user_id.eq(user.id),
                    group_owners_dsl::group_id.eq(group.id),
                ))
                .execute(&mut conn)
                .map_err(|_| Status::InternalServerError)?;
        }
        "remove" => {
            // Remove the user from members and owners
            diesel::delete(
                group_users_dsl::group_users
                    .filter(group_users_dsl::user_id.eq(user.id))
                    .filter(group_users_dsl::group_id.eq(group.id)),
            )
            .execute(&mut conn)
            .map_err(|_| Status::InternalServerError)?;

            diesel::delete(
                group_owners_dsl::group_owners
                    .filter(group_owners_dsl::user_id.eq(user.id))
                    .filter(group_owners_dsl::group_id.eq(group.id)),
            )
            .execute(&mut conn)
            .map_err(|_| Status::InternalServerError)?;
        }
        _ => return Err(Status::BadRequest),
    }

    Ok(Json(json!({ "status": "success" })))
}

#[openapi()]
#[post("/create-api-session-token", data = "<request>")]
pub fn create_api_session_token(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    request: Json<CreateSessionTokenRequest>,
) -> status::Custom<Json<CreateSessionTokenResponse>> {
    use crate::models::schema::schema::api_token::dsl as api_token_dsl;

    let mut conn = rdb.get().expect("Failed to get DB connection");

    // Check if the provided API token is valid
    let api_token_result: QueryResult<Api_Token> = api_token_dsl::api_token
        .filter(api_token_dsl::token_str.eq(&request.api_token))
        .filter(api_token_dsl::is_active.eq(true))
        .first::<Api_Token>(&mut conn);

    let api_token = match api_token_result {
        Ok(token) => token,
        Err(_) => {
            return status::Custom(
                Status::Unauthorized,
                Json(CreateSessionTokenResponse {
                    session_token: "".to_string(),
                }),
            );
        }
    };

    // Generate a JWT session token valid for 5 minutes
    let expiration = Utc::now() + Duration::minutes(20);
    let claims = APIClaims {
        sub: api_token.id.to_string(),
        exp: expiration.timestamp() as usize,
        group_id: api_token.parent_id, // Use parent_id from the Api_Token
        scopes: vec!["read".to_string(), "write".to_string()],
    };

    let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .expect("Failed to create session token");

    status::Custom(
        Status::Ok,
        Json(CreateSessionTokenResponse {
            session_token: token,
        }),
    )
}

/// this is used by the developers on their machine for creating a session. This assumes that there is an active session on the machine
#[openapi()]
#[post("/create-api-session-token-interactive/<group_identifier>")]
pub fn create_api_session_token_interactive(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    claims: Claims,
    group_identifier: String,
    groups_ownerships: GroupOwnerships,
) -> Result<Json<CreateSessionTokenResponse>, rocket::http::Status> {
    use crate::models::schema::schema::group::dsl as group_dsl;

    let mut conn = rdb.get().expect("Failed to get DB connection");

    let group = group_dsl::group
        .filter(group_dsl::identifier.eq(group_identifier.clone()))
        .first::<Group>(&mut conn)
        .optional()
        .map_err(|_| Status::InternalServerError)?;

    let group = group.ok_or(Status::NotFound)?;

    // Determine the scope based on ownership
    let scopes = if groups_ownerships.0.contains(&group_identifier.clone()) {
        vec!["read".to_string(), "write".to_string()]
    } else {
        vec!["read".to_string()]
    };

    // Generate a JWT session token valid for 5 minutes
    let expiration = Utc::now() + Duration::minutes(500);
    let claims = APIClaims {
        sub: group.identifier,
        exp: expiration.timestamp() as usize,
        group_id: group.id, // Use parent_id from the Api_Token
        scopes,
    };

    let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .expect("Failed to create session token");

    Ok(Json(CreateSessionTokenResponse {
        session_token: token,
    }))
}

#[openapi()]
#[get("/api-tokens/<group_identifier>")]
pub fn get_api_tokens_by_group(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    group_identifier: String,
) -> Result<Json<Vec<GroupApiTokenResponse>>, Status> {
    use crate::models::schema::schema::api_token::dsl as api_token_dsl;
    use crate::models::schema::schema::group::dsl as group_dsl;

    // Acquire a database connection from the pool
    let mut conn = rdb.get().map_err(|_| Status::InternalServerError)?;

    // Step 1: Retrieve the group based on the provided group_identifier
    let group = group_dsl::group
        .filter(group_dsl::identifier.eq(&group_identifier))
        .first::<Group>(&mut conn)
        .optional()
        .map_err(|_| Status::InternalServerError)?;

    // If the group does not exist, return a 404 Not Found error
    let group = match group {
        Some(g) => g,
        None => {
            return Err(Status::NotFound);
        }
    };

    // Step 2: Retrieve all API tokens associated with the group's primary key (group.id)
    let tokens = api_token_dsl::api_token
        .filter(api_token_dsl::parent_id.eq(group.id))
        .load::<Api_Token>(&mut conn)
        .map_err(|_| Status::InternalServerError)?;

    // Step 3: Map the retrieved tokens to the response struct
    let response: Vec<GroupApiTokenResponse> = tokens
        .into_iter()
        .map(|t| GroupApiTokenResponse {
            expiry_date: t.expiry_date,
            created_at: t.created_at,
            is_active: t.is_active,
            name: t.name,
            pk: t.id,
        })
        .collect();

    // Step 4: Return the response with a 200 OK status
    Ok(Json(response))
}

#[openapi()]
#[put("/api-tokens/<token_id>/deactivate")]
pub fn deactivate_api_token(
    rdb: &State<Pool<ConnectionManager<PgConnection>>>,
    token_id: i64,
) -> Result<Json<MessageResponse>, rocket::http::Status> {
    use crate::models::schema::schema::api_token::dsl::*;

    // Acquire a database connection from the pool
    let mut conn = rdb.get().map_err(|_| Status::InternalServerError)?;

    // Step 1: Find the API token by its ID
    let token = api_token
        .find(token_id)
        .first::<Api_Token>(&mut conn)
        .optional()
        .map_err(|_| Status::InternalServerError)?;

    // If the token does not exist, return a 404 Not Found error
    match token {
        Some(t) => t,
        None => {
            return Err(Status::NotFound);
        }
    };

    // Step 2: Deactivate the token (setting `is_active` to false)
    diesel::update(api_token.filter(id.eq(token_id)))
        .set(is_active.eq(false))
        .execute(&mut conn)
        .map_err(|_| Status::InternalServerError)?;

    // Step 3: Return a success message
    Ok(Json(MessageResponse {
        message: format!("API token with id '{}' has been deactivated", token_id),
    }))
}
