#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
use chrono::offset::Utc;
use chrono::DateTime;
use chrono::NaiveDate;
use diesel::Associations;
use diesel::Identifiable;
use diesel::Insertable;
use diesel::{deserialize::Queryable, table, Selectable};
use rocket::serde::Deserialize;
use schemars::JsonSchema;
use serde::Serialize;

pub mod schema {
    use diesel::table;

    table! {
        user (id) {
            #[max_length = 40]
            first_name ->Nullable<Varchar>,
            #[max_length = 40]
            last_name ->Nullable<Varchar>,
            #[max_length = 40]
            middle_name ->Nullable<Varchar>,
            #[max_length = 100]
            email_id ->Varchar,
            #[max_length = 15]
            mobile_number ->Nullable<Varchar>,
            created_at ->Timestamptz,
            updated_at ->Timestamptz,
            #[max_length = 400]
            password_hash ->Nullable<Varchar>,
            id ->BigInt,

        }
    }

    table! {
        token (id) {
            #[max_length = 400]
            session_hash ->Nullable<Varchar>,
            user_id ->BigInt,
            app_id ->BigInt,
            id ->BigInt,

        }
    }

    table! {
        app (id) {
            #[max_length = 150]
            client_id ->Varchar,
            #[max_length = 50]
            name ->Varchar,
            id ->BigInt,

        }
    }

    table! {
        group (id) {
            #[max_length = 50]
            identifier ->Varchar,
            id ->BigInt,

        }
    }

    table! {
        group_users (id) {
            id ->Int8,
            user_id ->Int8,
            group_id ->Int8,

        }
    }

    diesel::joinable!(token -> user (user_id));
    diesel::joinable!(token -> app (app_id));

    diesel::allow_tables_to_appear_in_same_query!(user, token, app, group, group_users,);
}

use schema::{app, group, group_users, token, user};

#[derive(Queryable, Debug, Selectable, Serialize, Deserialize, JsonSchema, Identifiable)]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(table_name = user)]
pub struct User {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub middle_name: Option<String>,
    pub email_id: String,
    pub mobile_number: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub password_hash: Option<String>,
    pub id: i64,
}

#[derive(
    Queryable, Debug, Selectable, Serialize, Deserialize, JsonSchema, Identifiable, Associations,
)]
#[diesel(belongs_to(User, foreign_key = user_id))]
#[diesel(belongs_to(App, foreign_key = app_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(table_name = token)]
pub struct Token {
    pub session_hash: Option<String>,
    pub user_id: i64,
    pub app_id: i64,
    pub id: i64,
}

#[derive(Queryable, Debug, Selectable, Serialize, Deserialize, JsonSchema, Identifiable)]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(table_name = app)]
pub struct App {
    pub client_id: String,
    pub name: String,
    pub id: i64,
}

#[derive(Queryable, Debug, Selectable, Serialize, Deserialize, JsonSchema, Identifiable)]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(table_name = group)]
pub struct Group {
    pub identifier: String,
    pub id: i64,
}

#[derive(
    Queryable, Debug, Selectable, Serialize, Deserialize, JsonSchema, Identifiable, Associations,
)]
#[diesel(belongs_to(User, foreign_key = user_id))]
#[diesel(belongs_to(Group, foreign_key = group_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(table_name = group_users)]
pub struct Group_User {
    pub id: i64,
    pub user_id: i64,
    pub group_id: i64,
}

#[derive(Queryable, Debug, Selectable, Serialize, Deserialize, Insertable, JsonSchema)]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(table_name = user)]
pub struct UserInsertable {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub middle_name: Option<String>,
    pub email_id: String,
    pub mobile_number: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub password_hash: Option<String>,
}

#[derive(
    Queryable, Debug, Selectable, Serialize, Deserialize, Insertable, JsonSchema, Associations,
)]
#[diesel(belongs_to(User, foreign_key = user_id))]
#[diesel(belongs_to(App, foreign_key = app_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(table_name = token)]
pub struct TokenInsertable {
    pub session_hash: Option<String>,
    pub user_id: i64,
    pub app_id: i64,
}

#[derive(Queryable, Debug, Selectable, Serialize, Deserialize, Insertable, JsonSchema)]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(table_name = app)]
pub struct AppInsertable {
    pub client_id: String,
    pub name: String,
}

#[derive(Queryable, Debug, Selectable, Serialize, Deserialize, Insertable, JsonSchema)]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(table_name = group)]
pub struct GroupInsertable {
    pub identifier: String,
}

#[derive(
    Queryable, Debug, Selectable, Serialize, Deserialize, Insertable, JsonSchema, Associations,
)]
#[diesel(belongs_to(User, foreign_key = user_id))]
#[diesel(belongs_to(Group, foreign_key = group_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(table_name = group_users)]
pub struct Group_UserInsertable {
    pub user_id: i64,
    pub group_id: i64,
}
