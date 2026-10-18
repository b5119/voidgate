//! Query-log action labels with a stable on-disk string mapping.
//!
//! The `action` column stores the lowercase labels returned by
//! [`Action::as_str`]; changing them is a schema-visible break.

use super::error::StorageError;

/// The outcome recorded for a query.
///
/// `REFUSED` (an ACL rejection) is deliberately **not** representable: those
/// queries are never logged, so the type makes the omission explicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Action {
    /// Allowlist match: forwarded upstream, never sinkholed.
    Allowed,
    /// Denylist or blocklist match: answered with the sinkhole address.
    Blocked,
    /// No rule matched: forwarded upstream unchanged.
    Forwarded,
    /// The upstream lookup failed; the client got `SERVFAIL`.
    Servfail,
}

impl Action {
    /// The stable lowercase label stored in the `action` column.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Blocked => "blocked",
            Self::Forwarded => "forwarded",
            Self::Servfail => "servfail",
        }
    }

    /// Parses a stored label back into an [`Action`].
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::UnknownAction`] for any value that is not one
    /// of the four labels written by [`Action::as_str`].
    pub fn parse(value: &str) -> Result<Self, StorageError> {
        match value {
            "allowed" => Ok(Self::Allowed),
            "blocked" => Ok(Self::Blocked),
            "forwarded" => Ok(Self::Forwarded),
            "servfail" => Ok(Self::Servfail),
            other => Err(StorageError::UnknownAction {
                value: other.to_owned(),
            }),
        }
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
