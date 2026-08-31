//! Writing AFF4 containers.
//!
//! **This is the only module permitted to open a write handle.** Everything
//! else in this crate is covered by `clippy.toml`'s deny-lists and the scan in
//! `tests/read_only_guard.rs`, which together prove the read path cannot modify
//! evidence. That proof matters more now than it did when the crate could not
//! write at all, so it is scoped rather than removed.
//!
//! Writing here is still not unrestricted: [`guard`] refuses any write handle
//! targeting a path registered as an acquisition source, and [`sink`] is the
//! single place a file is created.

pub mod acquire;
pub mod aff4_source;
pub mod bevy;
pub mod container_writer;
pub mod dedupe;
pub mod device;
pub mod guard;
pub mod logical;
pub mod map_writer;
pub mod scan;
pub mod sink;
pub mod split_writer;
pub mod stream_writer;
pub mod turtle;
pub mod zip_writer;
