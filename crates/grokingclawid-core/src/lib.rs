//! GrokingClawID Core Library
//!
//! Provides cryptographic identity management for AI agents:
//! - Ed25519 + ML-DSA-65 (post-quantum) hybrid signing
//! - Agent card issuance and verification
//! - Tamper-evident audit logging
//! - Challenge-response verification protocol
//! - RFC 9421 HTTP message signatures
//! - IOTA wallet integration (feature-gated)

pub mod crypto;
pub mod models;
pub mod audit;
pub mod challenge;
pub mod httpsig;

#[cfg(feature = "wallet")]
pub mod iota;

#[cfg(feature = "wallet")]
pub mod ws;
