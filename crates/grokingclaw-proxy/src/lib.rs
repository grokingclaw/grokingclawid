//! GrokingClaw Sidecar Proxy
//!
//! Every agent gets one. ALL outbound HTTP traffic goes through it.
//! The proxy enforces scope, signs requests with the agent's identity,
//! and logs every action to the audit trail.
//!
//! This is the piece that makes ANY agent GrokingClawID-compliant
//! without changing a single line of their code.

pub mod scope;
pub mod signer;
pub mod audit;
pub mod server;
