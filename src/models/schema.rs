#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
use diesel::Insertable;
use chrono::NaiveDate;
use diesel::{deserialize::Queryable, Selectable};
use schemars::JsonSchema;
use serde::Serialize;
use chrono::offset::Utc;
use chrono::DateTime;
use diesel::Identifiable;
use diesel::Associations;
use rocket::serde::Deserialize;

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
            is_root ->Bool,
            id ->BigInt,
            
        }
    }
    
    table! {
        token (id) {
            #[max_length = 400]
            session_hash ->Nullable<Varchar>,
            user_id ->BigInt,
            app_id ->Nullable<BigInt>,
            id ->BigInt,
            
        }
    }
    
    table! {
        app (id) {
            #[max_length = 150]
            client_id ->Varchar,
            #[max_length = 50]
            name ->Varchar,
            #[max_length = 200]
            logo_url ->Nullable<Varchar>,
            disabled ->Bool,
            #[max_length = 100]
            app_url_dev ->Nullable<Varchar>,
            #[max_length = 100]
            app_url_stage ->Nullable<Varchar>,
            #[max_length = 100]
            app_url_prod ->Nullable<Varchar>,
            id ->BigInt,
            
        }
    }
    
    table! {
        group (id) {
            #[max_length = 50]
            identifier ->Varchar,
            disabled ->Bool,
            #[max_length = 100]
            short_text ->Nullable<Varchar>,
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
    
    table! {
        group_owners (id) {
            id ->Int8,
            user_id ->Int8,
            group_id ->Int8,
            
        }
    }
    
    
        
    
        diesel::joinable!(token -> user (user_id));diesel::joinable!(token -> app (app_id));
    
        
    
        diesel::joinable!(group_users -> user (user_id));diesel::joinable!(group_owners -> user (user_id));
    
        
    
        
    

    diesel::allow_tables_to_appear_in_same_query!(
        user,
        token,
        app,
        group,
        group_users,
        group_owners,
        
    );
}

use schema::{ user,token,app,group,group_users,group_owners, };



#[derive(Queryable, Debug, Selectable, Serialize, Deserialize, JsonSchema,Identifiable)]

#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(table_name = user)]
pub struct User {
    pub first_name:Option<String>,
    pub last_name:Option<String>,
    pub middle_name:Option<String>,
    pub email_id:String,
    pub mobile_number:Option<String>,
    pub created_at:DateTime<Utc>,
    pub updated_at:DateTime<Utc>,
    pub password_hash:Option<String>,
    pub is_root:bool,
    pub id:i64,
    
}


#[derive(Queryable, Debug, Selectable, Serialize, Deserialize, JsonSchema,Identifiable,Associations)]
#[diesel(belongs_to(User, foreign_key = user_id))]#[diesel(belongs_to(App, foreign_key = app_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(table_name = token)]
pub struct Token {
    pub session_hash:Option<String>,
    pub user_id:i64,
    pub app_id:Option<i64>,
    pub id:i64,
    
}


#[derive(Queryable, Debug, Selectable, Serialize, Deserialize, JsonSchema,Identifiable)]

#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(table_name = app)]
pub struct App {
    pub client_id:String,
    pub name:String,
    pub logo_url:Option<String>,
    pub disabled:bool,
    pub app_url_dev:Option<String>,
    pub app_url_stage:Option<String>,
    pub app_url_prod:Option<String>,
    pub id:i64,
    
}


#[derive(Queryable, Debug, Selectable, Serialize, Deserialize, JsonSchema,Identifiable)]

#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(table_name = group)]
pub struct Group {
    pub identifier:String,
    pub disabled:bool,
    pub short_text:Option<String>,
    pub id:i64,
    
}


#[derive(Queryable, Debug, Selectable, Serialize, Deserialize, JsonSchema,Identifiable,Associations)]
#[diesel(belongs_to(User, foreign_key = user_id))]#[diesel(belongs_to(Group, foreign_key = group_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(table_name = group_users)]
pub struct Group_Users {
    pub id:i64,
    pub user_id:i64,
    pub group_id:i64,
    
}


#[derive(Queryable, Debug, Selectable, Serialize, Deserialize, JsonSchema,Identifiable,Associations)]
#[diesel(belongs_to(User, foreign_key = user_id))]#[diesel(belongs_to(Group, foreign_key = group_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(table_name = group_owners)]
pub struct Group_Owners {
    pub id:i64,
    pub user_id:i64,
    pub group_id:i64,
    
}




#[derive(Queryable, Debug, Selectable, Serialize, Deserialize, Insertable, JsonSchema)]

#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(table_name = user)]
pub struct UserInsertable {
    pub first_name:Option<String>,
    pub last_name:Option<String>,
    pub middle_name:Option<String>,
    pub email_id:String,
    pub mobile_number:Option<String>,
    pub created_at:DateTime<Utc>,
    pub updated_at:DateTime<Utc>,
    pub password_hash:Option<String>,
    pub is_root:bool,
    
}


#[derive(Queryable, Debug, Selectable, Serialize, Deserialize, Insertable, JsonSchema,Associations)]
#[diesel(belongs_to(User, foreign_key = user_id))]#[diesel(belongs_to(App, foreign_key = app_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(table_name = token)]
pub struct TokenInsertable {
    pub session_hash:Option<String>,
    pub user_id:i64,
    pub app_id:Option<i64>,
    
}


#[derive(Queryable, Debug, Selectable, Serialize, Deserialize, Insertable, JsonSchema)]

#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(table_name = app)]
pub struct AppInsertable {
    pub client_id:String,
    pub name:String,
    pub logo_url:Option<String>,
    pub disabled:bool,
    pub app_url_dev:Option<String>,
    pub app_url_stage:Option<String>,
    pub app_url_prod:Option<String>,
    
}


#[derive(Queryable, Debug, Selectable, Serialize, Deserialize, Insertable, JsonSchema)]

#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(table_name = group)]
pub struct GroupInsertable {
    pub identifier:String,
    pub disabled:bool,
    pub short_text:Option<String>,
    
}


#[derive(Queryable, Debug, Selectable, Serialize, Deserialize, Insertable, JsonSchema,Associations)]
#[diesel(belongs_to(User, foreign_key = user_id))]#[diesel(belongs_to(Group, foreign_key = group_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(table_name = group_users)]
pub struct Group_UsersInsertable {
    pub user_id:i64,
    pub group_id:i64,
    
}


#[derive(Queryable, Debug, Selectable, Serialize, Deserialize, Insertable, JsonSchema,Associations)]
#[diesel(belongs_to(User, foreign_key = user_id))]#[diesel(belongs_to(Group, foreign_key = group_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(table_name = group_owners)]
pub struct Group_OwnersInsertable {
    pub user_id:i64,
    pub group_id:i64,
    
}
