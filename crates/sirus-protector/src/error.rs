//! Protector error type.

use core::fmt;

use sirus_binfmt::FormatError;

/// Errors produced by the protector.
#[derive(Debug, PartialEq, Eq)]
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

#[cfg(test)]
mod tests {
    use super::ProtectError;
    use sirus_binfmt::FormatError;
    use sirus_core::error::CoreError;

    #[test]
    fn every_error_type_has_a_message_and_source() {
        let errors = [
            ProtectError::Usage("usage".to_owned()),
            ProtectError::Format(FormatError::Malformed),
            ProtectError::Core(CoreError::InvalidPlan),
            ProtectError::Io("io".to_owned()),
            ProtectError::Tool("tool".to_owned()),
            ProtectError::Internal("internal".to_owned()),
        ];
        for error in errors {
            assert_ne!(error.to_string(), "");
            assert!(std::error::Error::source(&error).is_none());
        }
        let context = ProtectError::context("context", ProtectError::Tool("inner".to_owned()));
        assert_ne!(context.to_string(), "");
        assert!(std::error::Error::source(&context).is_some());
    }

    #[test]
    fn constructors_and_conversions_are_total() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let errors = [
            ProtectError::io("context", &io),
            ProtectError::internal("internal"),
            ProtectError::tool("tool"),
            ProtectError::usage("usage"),
            ProtectError::from(FormatError::Bounds),
            ProtectError::from(CoreError::InvalidPlan),
        ];
        for error in errors {
            assert_ne!(error.to_string(), "");
        }
    }
}
