//! Shared modules included verbatim by the workspace crates and by generated
//! injected runtimes. Keeping one source prevents compiler/runtime drift.

pub mod chacha;
pub mod cipher;
pub mod derive;
pub mod format;
pub mod sip;
