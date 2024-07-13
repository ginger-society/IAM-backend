#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
use diesel::Insertable;
use chrono::NaiveDate;
use diesel::{deserialize::Queryable, table, Selectable};
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
            #[max_length = 200]
            password_hash ->Nullable<Varchar>,
            id ->BigInt,
            
        }
    }
    
    table! {
        token (id) {
            #[max_length = 200]
            session_hash ->Nullable<Varchar>,
            user_id ->BigInt,
            id ->BigInt,
            
        }
    }
    
    
        
    
        diesel::joinable!(token -> user (user_id));
    

    diesel::allow_tables_to_appear_in_same_query!(
        user,
        token,
        
    );
}

use schema::{ user,token, };



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
    pub id:i64,
    
}


#[derive(Queryable, Debug, Selectable, Serialize, Deserialize, JsonSchema,Identifiable,Associations)]
#[diesel(belongs_to(User, foreign_key = user_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(table_name = token)]
pub struct Token {
    pub session_hash:Option<String>,
    pub user_id:i64,
    pub id:i64,
    
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
    
}


#[derive(Queryable, Debug, Selectable, Serialize, Deserialize, Insertable, JsonSchema,Associations)]
#[diesel(belongs_to(User, foreign_key = user_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(table_name = token)]
pub struct TokenInsertable {
    pub session_hash:Option<String>,
    pub user_id:i64,
    
}
