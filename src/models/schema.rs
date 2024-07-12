#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

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
            first_name ->Varchar,
            #[max_length = 40]
            last_name ->Varchar,
            #[max_length = 40]
            middle_name ->Nullable<Varchar>,
            #[max_length = 100]
            email_id ->Varchar,
            #[max_length = 15]
            mobile_number ->Varchar,
            created_at ->Timestamptz,
            updated_at ->Timestamptz,
            id ->BigInt,
            
        }
    }
    
    table! {
        token (id) {
            #[max_length = 100]
            password_hash ->Varchar,
            #[max_length = 100]
            session_hash ->Varchar,
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
    pub first_name:String,
    pub last_name:String,
    pub middle_name:Option<String>,
    pub email_id:String,
    pub mobile_number:String,
    pub created_at:DateTime<Utc>,
    pub updated_at:DateTime<Utc>,
    pub id:i64,
    
}


#[derive(Queryable, Debug, Selectable, Serialize, Deserialize, JsonSchema,Identifiable,Associations)]
#[diesel(belongs_to(User, foreign_key = user_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(table_name = token)]
pub struct Token {
    pub password_hash:String,
    pub session_hash:String,
    pub user_id:i64,
    pub id:i64,
    
}




#[derive(Queryable, Debug, Selectable, Serialize, Deserialize, JsonSchema)]

#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(table_name = user)]
pub struct UserInsertable {
    pub first_name:String,
    pub last_name:String,
    pub middle_name:Option<String>,
    pub email_id:String,
    pub mobile_number:String,
    pub created_at:DateTime<Utc>,
    pub updated_at:DateTime<Utc>,
    
}


#[derive(Queryable, Debug, Selectable, Serialize, Deserialize, JsonSchema,Associations)]
#[diesel(belongs_to(User, foreign_key = user_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(table_name = token)]
pub struct TokenInsertable {
    pub password_hash:String,
    pub session_hash:String,
    pub user_id:i64,
    
}
