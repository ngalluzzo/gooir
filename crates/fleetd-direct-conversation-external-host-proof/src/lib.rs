//! Proof-local durable host boundary for the Fleetd direct-conversation proof.
//!
//! This crate owns non-secret target locking, durable attempt state, and
//! proof-local qualification/private materialization of exact package-owned
//! native artifacts. It is not a generic GOOIR runtime, native process API,
//! HTTP adapter, or plugin interface. Process execution and semantic
//! interpretation are deliberately outside this checkpoint.

#![forbid(unsafe_code)]

pub mod journal;
pub mod native;
pub mod target;
