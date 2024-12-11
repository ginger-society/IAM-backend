use rocket_okapi::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, JsonSchema)]
pub struct RequestPasswordRequest {
    pub email_id: String,
    pub app_id: String,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RegisterRequestValue {
    pub email: String,
    pub hashed_password: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct CreateGroupRequest {
    pub id: String,
    pub description: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct UpdateProfileRequest {
    pub first_name: Option<String>,
    pub middle_name: Option<String>,
    pub last_name: Option<String>,
    pub mobile_number: Option<String>,
}
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub app_id: String,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    pub client_id: String,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct ValidateTokenRequest {
    pub access_token: String,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct ChangePasswordRequest {
    pub email: String,
    pub current_password: String,
    pub new_password: String,
}

#[derive(Deserialize, Serialize, Debug, JsonSchema)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub new_password: String,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct CreateApiTokenRequest {
    pub days_to_expire: i64,
    pub name: String,
    pub group_identifier: String, // Changed to i64 for consistency with your schema
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct LogoutRequest {
    pub refresh_token: String,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct CreateSessionTokenRequest {
    pub api_token: String,
}
