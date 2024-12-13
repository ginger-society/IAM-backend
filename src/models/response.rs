use chrono::{DateTime, NaiveDate, Utc};
use rocket_okapi::JsonSchema;
use serde::{Deserialize, Serialize};
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct AppResponse {
    pub name: String,
    pub logo_url: Option<String>,
    pub app_url_dev: Option<String>,
    pub app_url_stage: Option<String>,
    pub app_url_prod: Option<String>,
    pub tnc_link: Option<String>,
    pub allow_registration: bool,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct RefreshTokenResponse {
    pub access_token: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ValidateTokenResponse {
    pub sub: String,
    pub exp: usize,
    pub user_id: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub middle_name: Option<String>,
    pub client_id: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ValidateAPITokenResponse {
    pub sub: String,
    pub exp: usize,
    pub scopes: Vec<String>,
    pub group_id: i64,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct CreateApiTokenResponse {
    pub api_token: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct UserInfoResponse {
    pub first_name: String,
    pub last_name: String,
    pub middle_name: Option<String>,
    pub pk: i64,
    pub is_admin: bool,
    pub email_id: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct CreateSessionTokenResponse {
    pub session_token: String,
}

/// Struct to represent the API token response
#[derive(Serialize, JsonSchema)]
pub struct GroupApiTokenResponse {
    pub expiry_date: NaiveDate,
    pub created_at: DateTime<Utc>,
    pub is_active: bool,
    pub name: String,
    pub pk: i64,
}

#[derive(Serialize, JsonSchema)]
pub struct AccessibleApp {
    pub name: String,
    pub logo_url: Option<String>,
    pub allow_registration: bool,
    pub tnc_link: Option<String>,
    pub description: Option<String>,
    pub app_url_dev: Option<String>,
    pub app_url_stage: Option<String>,
    pub app_url_prod: Option<String>,
}
