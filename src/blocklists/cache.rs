//! On-disk blocklist cache: atomic writes, HTTP fetching with caps, and the
//! refresh pass driven by `voidgate update-lists`.
//!
//! Refresh rules for URL lists — the previous cache file is **kept** (and the
//! reason reported) when the fetch fails, the body exceeds
//! `max_fetch_bytes`, the download parses to zero domains, or it retains less
//! than `min_retained_percent` of the previous domain count. Successful
//! downloads are written to `<name>.tmp` and atomically renamed onto
//! `<cache_dir>/<name>`. Local `file` lists are never cached: they are read
//! from their source path at load time.

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::blocklists::error::BlocklistError;
use crate::blocklists::parser;
use crate::config::{is_cache_safe_name, BlocklistKind, BlocklistSource, BlocklistsConfig};

/// What happened to one blocklist during a refresh pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// A fresh copy was fetched and atomically written to the cache.
    Updated {
        /// Number of domains the new copy parsed to.
        domains: usize,
    },
    /// The previous cache file was kept unchanged.
    KeptOld {
        /// Why the refresh was rejected.
        reason: KeepReason,
    },
    /// A `type: file` list: read from source at load, never cached.
    LocalFile,
}

/// Why a refresh was rejected in favour of the previous cache file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeepReason {
    /// The HTTP fetch failed (connect, timeout, status, size cap, …).
    FetchFailed {
        /// Rendered [`BlocklistError`] message.
        message: String,
    },
    /// The fetch succeeded but the cache could not be written.
    WriteFailed {
        /// Rendered [`BlocklistError`] message.
        message: String,
    },
    /// The download parsed to zero domains.
    Empty,
    /// The download retained less than `min_retained_percent` of the
    /// previous domain count.
    Shrink {
        /// Domains in the previous cache file.
        previous: usize,
        /// Domains in the rejected download.
        current: usize,
    },
}

/// Per-list result of a refresh pass, suitable for CLI display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshReport {
    /// The blocklist name from the config.
    pub name: String,
    /// What happened to it.
    pub outcome: RefreshOutcome,
}

impl fmt::Display for RefreshReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.outcome {
            RefreshOutcome::Updated { domains } => {
                write!(f, "{}: updated ({domains} domains)", self.name)
            }
            RefreshOutcome::KeptOld { reason } => {
                write!(f, "{}: kept previous cache ({reason})", self.name)
            }
            RefreshOutcome::LocalFile => write!(
                f,
                "{}: local file (read from source at load, not cached)",
                self.name
            ),
        }
    }
}

impl fmt::Display for KeepReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeepReason::FetchFailed { message } => write!(f, "fetch failed: {message}"),
            KeepReason::WriteFailed { message } => write!(f, "cache write failed: {message}"),
            KeepReason::Empty => write!(f, "download parsed to 0 domains"),
            KeepReason::Shrink { previous, current } => {
                write!(f, "download shrank from {previous} to {current} domains")
            }
        }
    }
}

/// Builds the canonical cache path for `name`, rejecting unsafe names.
///
/// # Errors
///
/// Returns [`BlocklistError::InvalidName`] when `name` is not
/// `[a-z0-9_-]+` (path-traversal guard; config validation enforces the same
/// rule).
pub fn cache_path(cache_dir: &Path, name: &str) -> Result<PathBuf, BlocklistError> {
    if !is_cache_safe_name(name) {
        return Err(BlocklistError::InvalidName {
            name: name.to_owned(),
        });
    }
    Ok(cache_dir.join(name))
}

/// Writes `bytes` to `<cache_dir>/<name>.tmp` then renames onto
/// `<cache_dir>/<name>` (atomic on the same filesystem).
///
/// A failed rename leaves the previous cache file untouched and removes the
/// temporary file.
///
/// # Errors
///
/// Returns [`BlocklistError::InvalidName`] for unsafe names, or
/// [`BlocklistError::Io`] when the write or rename fails.
pub fn write_atomic(cache_dir: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf, BlocklistError> {
    let final_path = cache_path(cache_dir, name)?;
    let tmp_path = cache_dir.join(format!("{name}.tmp"));
    std::fs::write(&tmp_path, bytes).map_err(|source| BlocklistError::Io {
        operation: "write temporary cache file",
        path: tmp_path.clone(),
        source,
    })?;
    if let Err(source) = std::fs::rename(&tmp_path, &final_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(BlocklistError::Io {
            operation: "rename cache file",
            path: final_path,
            source,
        });
    }
    Ok(final_path)
}

/// GETs `url`, enforcing the `max_bytes` cap against both the declared
/// `Content-Length` and the streamed body.
///
/// # Errors
///
/// Returns a [`BlocklistError`] on transport failure, non-2xx status, or a
/// body over `max_bytes`.
pub async fn fetch(
    client: &reqwest::Client,
    url: &str,
    max_bytes: u64,
) -> Result<Vec<u8>, BlocklistError> {
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|source| BlocklistError::Fetch {
            url: url.to_owned(),
            source: Box::new(source),
        })?;
    let status = response.status();
    if !status.is_success() {
        return Err(BlocklistError::HttpStatus {
            url: url.to_owned(),
            status,
        });
    }
    if let Some(length) = response.content_length() {
        if length > max_bytes {
            return Err(BlocklistError::TooLarge {
                url: url.to_owned(),
                limit: max_bytes,
            });
        }
    }
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|source| BlocklistError::Fetch {
            url: url.to_owned(),
            source: Box::new(source),
        })?
    {
        if body.len() as u64 + chunk.len() as u64 > max_bytes {
            return Err(BlocklistError::TooLarge {
                url: url.to_owned(),
                limit: max_bytes,
            });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Refreshes every `url` list into `config.cache_dir`; reports each list.
///
/// Creates the cache directory if needed. Per-list fetch/rejection failures
/// are reported in the returned [`RefreshReport`]s; only a failure to create
/// the cache directory (or build the HTTP client) is returned as `Err`.
///
/// # Errors
///
/// Returns [`BlocklistError::Io`] when the cache directory cannot be created,
/// or [`BlocklistError::HttpClient`] when the client cannot be built.
pub async fn refresh_all(config: &BlocklistsConfig) -> Result<Vec<RefreshReport>, BlocklistError> {
    std::fs::create_dir_all(&config.cache_dir).map_err(|source| BlocklistError::Io {
        operation: "create cache directory",
        path: config.cache_dir.clone(),
        source,
    })?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(config.fetch_timeout_secs))
        .build()
        .map_err(|source| BlocklistError::HttpClient(source.to_string()))?;

    let mut reports = Vec::with_capacity(config.lists.len());
    for list in &config.lists {
        let outcome = match list.kind {
            BlocklistKind::File => RefreshOutcome::LocalFile,
            BlocklistKind::Url => refresh_one(&client, config, list).await,
        };
        reports.push(RefreshReport {
            name: list.name.clone(),
            outcome,
        });
    }
    Ok(reports)
}

/// Fetches and caches one URL list, or explains why the old file was kept.
async fn refresh_one(
    client: &reqwest::Client,
    config: &BlocklistsConfig,
    list: &BlocklistSource,
) -> RefreshOutcome {
    let bytes = match fetch(client, &list.source, config.max_fetch_bytes).await {
        Ok(bytes) => bytes,
        Err(error) => {
            return RefreshOutcome::KeptOld {
                reason: KeepReason::FetchFailed {
                    message: error.to_string(),
                },
            };
        }
    };
    let domains = parser::parse_bytes(&bytes);
    if domains.is_empty() {
        return RefreshOutcome::KeptOld {
            reason: KeepReason::Empty,
        };
    }
    if let Some(previous) = cached_domain_count(config, &list.name) {
        let retained = domains.len().saturating_mul(100);
        let floor = previous.saturating_mul(config.min_retained_percent as usize);
        if previous > 0 && retained < floor {
            return RefreshOutcome::KeptOld {
                reason: KeepReason::Shrink {
                    previous,
                    current: domains.len(),
                },
            };
        }
    }
    match write_atomic(&config.cache_dir, &list.name, &bytes) {
        Ok(_) => RefreshOutcome::Updated {
            domains: domains.len(),
        },
        Err(error) => RefreshOutcome::KeptOld {
            reason: KeepReason::WriteFailed {
                message: error.to_string(),
            },
        },
    }
}

/// Domain count currently in the cache file for `name`, if readable.
fn cached_domain_count(config: &BlocklistsConfig, name: &str) -> Option<usize> {
    let path = cache_path(&config.cache_dir, name).ok()?;
    let bytes = std::fs::read(path).ok()?;
    Some(parser::parse_bytes(&bytes).len())
}
