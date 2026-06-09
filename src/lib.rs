// Public library interface for ORADAZ
// This module exposes the public API and utilities for testing

// No-panic gate for the collection path (this lib crate holds `collect` + `utils`).
// A panic during a collection either aborts the process (release profile is
// `panic = "abort"`) or strands the pipeline counter — both leave a dangling
// `.mla.tmp` instead of a clean `.mla` / `.broken`. Denying these clippy lints on
// production code locks in the "no reachable panic" property so a future edit cannot
// silently reintroduce one. Test modules are exempt: `cfg(test)` is off under the CI
// `cargo clippy` (no `--all-targets`), so `#[cfg(test)]` code is not compiled there.
// `src/main.rs` is a *separate* bin crate and carries the same block; `src/inspect`
// opts out (read-only analysis tool, creates/renames no archive).
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented
)]

pub mod collect;
pub mod inspect;
pub mod utils;

pub const FL: usize = 25;
pub const VERSION: &str = "3.0.06.09";
pub const SCHEMA_URL: &str = "https://raw.githubusercontent.com/ANSSI-FR/ORADAZ/v3/schema.json";
pub const APP_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0";
pub const PUB_KEY: &[u8] = include_bytes!("keys/key.mlapub");
