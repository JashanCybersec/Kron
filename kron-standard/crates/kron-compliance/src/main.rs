//! `kron-compliance` binary entry point.
//!
//! In production this crate is used as a library from `kron-query-api`.
//! The binary provides a CLI for generating reports out-of-band (e.g. cron jobs).

fn main() {
    println!("kron-compliance: use the library API or kron-query-api REST endpoints.");
}
