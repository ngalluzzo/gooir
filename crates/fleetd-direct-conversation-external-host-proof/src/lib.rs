//! Proof-local durable host boundary for the Fleetd direct-conversation proof.
//!
//! This crate currently owns only non-secret target locking and durable attempt
//! state. It is not a generic GOOIR runtime, native process API, HTTP adapter,
//! or plugin interface. Process execution and semantic interpretation are
//! deliberately outside this checkpoint.

#![forbid(unsafe_code)]

pub mod journal;
pub mod target;
