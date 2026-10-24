//! Isolated Admin Control-Plane REST API (`/api/v1/*`), Authentication (`Local Argon2id` + `Keycloak OIDC`),
//! and Static PatternFly 6 SPA Asset Server.

pub mod api;
pub mod auth;
pub mod crypto;
