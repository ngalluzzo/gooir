//! Proof-local durable host boundary for the Fleetd direct-conversation proof.
//!
//! This crate owns non-secret target locking, durable attempt state, and
//! proof-local qualification/private materialization of exact package-owned
//! native artifacts. It is not a generic GOOIR runtime, native process API,
//! HTTP adapter, or plugin interface. Process execution is confined to the
//! proof-local supervisor primitive; semantic interpretation remains outside
//! that primitive.

#![deny(unsafe_code)]

pub mod driver;
pub mod journal;
pub mod native;
pub mod runtime;
pub mod supervisor;
pub mod target;
