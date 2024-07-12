## 
Fully working CRUD REST API example using 
- Rust (stable)
- Rocket.rs
- MongoDB
- PostgresSQL
- Diesel ORM

## 🚀 Features
- Establish MongoDB connection using rocket Adhoc fairing.
- Work with PostgresSQL usinf diesel ORM.
- Prometheus integration.
- Custom error handlings with rocket Responder and okapi OpenApiGenerator.
- CORS fairing and Counter fairing to demonstrate how fairing works.
- Example model Customer to demonstrate how Rust structs interact with MongoDB.
- Request guard using ApiKey.
- REST API endpoints with simple CRUD using Customer model.
- Implement Open API documentation using okapi.
- Test codes to test API endpoints.


## 🔧 Building and Testing

### debug mode
> cargo run

### release mode
> cargo build --release && cargo run --release


### unit testing
> cargo test

