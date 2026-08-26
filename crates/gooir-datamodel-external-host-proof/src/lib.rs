//! Proof-only external host for one installed data-model capability.
//!
//! This crate composes public package, planning, invocation, conformance, and
//! admission boundaries. It is deliberately not a GOOIR kernel runtime or a
//! stable generic host API: Fleetd must provide the second consumer before any
//! execution-host mechanism is promoted.

#![forbid(unsafe_code)]

pub mod journal;
pub mod wasm;
