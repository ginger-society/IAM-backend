//! SSH user-certificate generation — pure Rust, no ssh-keygen binary.
//!
//! Three endpoints, one per auth level:
//!   POST /ssh-cert/user-land   → Claims      (500-minute TTL)
//!   POST /ssh-cert/api-land    → APIClaims   (20-minute TTL)
//!   POST /ssh-cert/isc-land    → ISCClaims   (365-day TTL)
//!
//! Each endpoint:
//!   1. Generates a fresh ed25519 user keypair (ephemeral).
//!   2. Reads the CA private key from /etc/ssh-ca/ca_key (PEM-encoded ed25519).
//!   3. Signs a certificate for principal = claims.sub, with the appropriate TTL.
//!   4. Returns { private_key_pem, certificate_pem } so the caller can write
//!      ~/.ssh/id_ed25519 + ~/.ssh/id_ed25519-cert.pub.

use chrono::Utc;
use rand::Rng;
use rand::distributions::Alphanumeric;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::{post};
use rocket::State;
use rocket_okapi::openapi;
use serde::{Deserialize, Serialize};
use std::fs;

use ginger_shared_rs::rocket_utils::{APIClaims, Claims, ISCClaims};

use ssh_key::{
    PrivateKey, PublicKey,
    certificate::{Builder as CertBuilder, CertType},
    Algorithm,
    LineEnding,
};

// ── response ──────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SshCertResponse {
    /// PEM-encoded ed25519 private key (write to ~/.ssh/id_ed25519)
    pub private_key_pem: String,
    /// OpenSSH public key line (write to ~/.ssh/id_ed25519.pub)
    pub public_key: String,
    /// OpenSSH certificate line (write to ~/.ssh/id_ed25519-cert.pub)
    pub certificate: String,
    /// Human-readable validity window
    pub valid_for: String,
    /// Principal embedded in the cert
    pub principal: String,
}

// ── helpers ───────────────────────────────────────────────────────────────────

const CA_KEY_PATH: &str = "/etc/ssh-ca/ca_key";

/// Load the CA signing key from the well-known mount path.
fn load_ca_key() -> Result<PrivateKey, Status> {
    let pem = fs::read_to_string(CA_KEY_PATH).map_err(|e| {
        eprintln!("[ssh-cert] ❌ Cannot read CA key at {}: {}", CA_KEY_PATH, e);
        Status::InternalServerError
    })?;
    PrivateKey::from_openssh(&pem).map_err(|e| {
        eprintln!("[ssh-cert] ❌ Failed to parse CA key: {}", e);
        Status::InternalServerError
    })
}
fn issue_cert(principal: &str, ttl_seconds: u64) -> Result<SshCertResponse, Status> {
    // 1. Generate an ephemeral user keypair
    let user_key = PrivateKey::random(&mut rand::thread_rng(), Algorithm::Ed25519)
        .map_err(|e| {
            eprintln!("[ssh-cert] ❌ Keypair generation failed: {}", e);
            Status::InternalServerError
        })?;

    let user_pub: PublicKey = user_key.public_key().clone();

    // 2. Load the CA key
    let ca_key = load_ca_key()?;

    // 3. Build and sign the certificate
    let now = Utc::now().timestamp() as u64;
    let valid_after  = now.saturating_sub(10); // small clock-skew buffer
    let valid_before = now + ttl_seconds;

    let serial: u64 = rand::thread_rng().gen();
    let key_id = format!(
        "{}-ephemeral-{}",
        principal,
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(8)
            .map(char::from)
            .collect::<String>()
    );

    // new_with_random_nonce returns Result<&mut Builder>, so we get the builder
    // first, then chain the remaining setters on the &mut Builder reference.
    let mut rng = rand::thread_rng();
    
    
    let mut builder = CertBuilder::new_with_random_nonce(
        &mut rng,
        user_pub.clone(),
        valid_after,
        valid_before,
    )
    .map_err(|e| {
        eprintln!("[ssh-cert] ❌ CertBuilder::new_with_random_nonce failed: {}", e);
        Status::InternalServerError
    })?;

    builder.serial(serial);  // serial() returns &mut Builder directly, no Result

    builder
        .cert_type(CertType::User)
        .map_err(|e| {
            eprintln!("[ssh-cert] ❌ cert_type failed: {}", e);
            Status::InternalServerError
        })?
        .key_id(key_id)
        .map_err(|e| {
            eprintln!("[ssh-cert] ❌ key_id failed: {}", e);
            Status::InternalServerError
        })?
        .valid_principal(principal)
        .map_err(|e| {
            eprintln!("[ssh-cert] ❌ valid_principal failed: {}", e);
            Status::InternalServerError
        })?;

    let cert = builder
        .sign(&ca_key)
        .map_err(|e| {
            eprintln!("[ssh-cert] ❌ Certificate signing failed: {}", e);
            Status::InternalServerError
        })?;

    // 4. Serialise
    let private_key_pem = user_key
        .to_openssh(LineEnding::LF)
        .map_err(|_| Status::InternalServerError)?
        .to_string();

    let public_key  = &user_pub.to_openssh().map_err(|_| Status::InternalServerError)?;
    let certificate = cert.to_openssh().map_err(|_| Status::InternalServerError)?;

    let minutes = ttl_seconds / 60;
    let valid_for = if minutes >= 60 * 24 {
        format!("{} day(s)", minutes / (60 * 24))
    } else {
        format!("{} minute(s)", minutes)
    };

    Ok(SshCertResponse {
        private_key_pem,
        public_key: public_key.to_string(),
        certificate,
        valid_for,
        principal: principal.to_string(),
    })
}
// ── endpoints ─────────────────────────────────────────────────────────────────

/// Issue an SSH user certificate for an authenticated **user** (500-minute TTL).
#[openapi()]
#[post("/ssh-cert/user-land")]
pub fn ssh_cert_user_land(
    claims: Claims,
) -> Result<Json<SshCertResponse>, Status> {
    let principal = claims.sub;
    let ttl = 500 * 60; // 500 minutes
    let resp = issue_cert(&principal, ttl)?;
    println!("[ssh-cert] ✅ user-land cert issued for '{}' (500 min)", principal);
    Ok(Json(resp))
}

/// Issue an SSH user certificate for an **API token** caller (20-minute TTL).
#[openapi()]
#[post("/ssh-cert/api-land")]
pub fn ssh_cert_api_land(
    claims: APIClaims,
) -> Result<Json<SshCertResponse>, Status> {
    let principal = claims.sub;
    let ttl = 20 * 60; // 20 minutes
    let resp = issue_cert(&principal, ttl)?;
    println!("[ssh-cert] ✅ api-land cert issued for '{}' (20 min)", principal);
    Ok(Json(resp))
}

/// Issue an SSH user certificate for an **ISC** service caller (365-day TTL).
#[openapi()]
#[post("/ssh-cert/isc-land")]
pub fn ssh_cert_isc_land(
    claims: ISCClaims,
) -> Result<Json<SshCertResponse>, Status> {
    let principal = claims.sub;
    let ttl = 365 * 24 * 60 * 60; // 365 days
    let resp = issue_cert(&principal, ttl)?;
    println!("[ssh-cert] ✅ isc-land cert issued for '{}' (365 days)", principal);
    Ok(Json(resp))
}