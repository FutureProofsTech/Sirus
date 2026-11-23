//! Protector error type.

use core::fmt;

use sirus_binfmt::FormatError;

/// Errors produced by the protector.
#[derive(Debug)]
pub enum ProtectError {
    /// Command-line usage error.
    Usage(String),
    /// Binary format error.
    Format(FormatError),
    /// Compiler core error.
    Core(sirus_core::error::CoreError),
    /// Filesystem or process I/O error.
    Io(String),
    /// External tool failed.
    Tool(String),
    /// Internal invariant violation.
    Internal(String),
    /// Context wrapper around another error.
    Context(String, Box<Self>),
}

impl fmt::Display for ProtectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(message) => write!(formatter, "usage: {message}"),
            Self::Format(error) => write!(formatter, "binary format: {error}"),
            Self::Core(error) => write!(formatter, "compiler core: {error}"),
            Self::Io(message) => write!(formatter, "I/O: {message}"),
            Self::Tool(message) => write!(formatter, "tool failure: {message}"),
            Self::Internal(message) => write!(formatter, "internal error: {message}"),
            Self::Context(context, _) => formatter.write_str(context),
        }
    }
}

impl From<FormatError> for ProtectError {
    #[inline]
    fn from(error: FormatError) -> Self {
        Self::Format(error)
    }
}

impl From<sirus_core::error::CoreError> for ProtectError {
    #[inline]
    fn from(error: sirus_core::error::CoreError) -> Self {
        Self::Core(error)
    }
}

impl std::error::Error for ProtectError {
    #[inline]
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Context(_, source) => Some(source.as_ref()),
            _ => None,
        }
    }
}

impl ProtectError {
    /// Adds operation context to another error.
    #[inline]
    #[must_use]
    pub fn context(context: impl fmt::Display, source: Self) -> Self {
        Self::Context(format!("{context}"), Box::new(source))
    }

    /// Builds a contextual I/O error.
    #[inline]
    #[must_use]
    pub fn io(context: &str, error: &std::io::Error) -> Self {
        Self::Io(format!("{context}: {error}"))
    }

    /// Builds an internal error.
    #[inline]
    #[must_use]
    pub fn internal(context: &str) -> Self {
        Self::Internal(context.to_owned())
    }

    /// Builds a tool error.
    #[inline]
    #[must_use]
    pub fn tool(context: impl Into<String>) -> Self {
        Self::Tool(context.into())
    }

    /// Builds a usage error.
    #[inline]
    #[must_use]
    pub fn usage(context: impl Into<String>) -> Self {
        Self::Usage(context.into())
    }
}

/// Protector result alias.
pub type Result<T> = std::result::Result<T, ProtectError>;
