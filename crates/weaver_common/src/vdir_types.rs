// SPDX-License-Identifier: Apache-2.0

//! Lightweight version of the `vdir` module providing only type definitions.
//!
//! When the `io` feature is disabled (e.g., for WASM builds), this module provides
//! the `VirtualDirectoryPath` type without the heavy I/O dependencies (gix, openssl,
//! tempfile, etc.) needed by the full `VirtualDirectory` implementation.

use crate::vdir_types::VirtualDirectoryPath::{GitRepo, LocalArchive, LocalFolder, RemoteArchive};
use crate::Error;
use once_cell::sync::Lazy;
use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::str::FromStr;

/// Regex to parse a virtual directory path string.
///
/// Supports the following general format: `source[@refspec][\[sub_folder]]`
/// - `source`: The main path or URL.
/// - `refspec`: Optional Git refspec (tag, branch, commit).
/// - `sub_folder`: Optional path within the source (for archives/repos).
static REGISTRY_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(?P<source>.+?)(?:@(?P<refspec>.+?))?(?:\[(?P<sub_folder>.+?)])?$")
        .expect("Invalid regex")
});

/// Represents a virtual path pointing to a directory-like resource.
///
/// Supported formats include:
/// - **Local directories** (`/path/to/directory`)
/// - **Local archives** (`/path/to/archive.zip` or `/path/to/archive.tar.gz`)
/// - **Remote archives** (`https://example.com/archive.zip` or `.tar.gz`)
/// - **Git repositories** (`https://github.com/user/repo.git`)
///
/// Paths may optionally specify:
/// - A sub-folder within the archive or repository via `[sub_folder]`
/// - [Not Yet Implemented] A specific Git refspec (branch, tag, or commit) via `@refspec`
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "String")]
#[serde(into = "String")]
pub enum VirtualDirectoryPath {
    /// A virtual directory representing a local folder.
    LocalFolder {
        /// Path to a local folder
        path: String,
    },
    /// A virtual directory representing a local archive.
    LocalArchive {
        /// Path to a local archive
        path: String,
        /// Sub-folder within the archive containing the content of interest.
        sub_folder: Option<String>,
    },
    /// A virtual directory representing a remote archive containing the content of interest.
    RemoteArchive {
        /// URL of the remote archive
        url: String,
        /// Sub-folder within the archive containing the content of interest.
        sub_folder: Option<String>,
    },
    /// A virtual directory representing a git repository containing the content of interest.
    GitRepo {
        /// The URL of the Git repository to clone (supports HTTP(S) URLs).
        url: String,
        /// Specific tag, branch, or commit hash to checkout.
        refspec: Option<String>,
        /// Optional sub-folder path within the cloned repository to use as the root directory.
        /// If omitted, the repository root is used.
        sub_folder: Option<String>,
    },
}

fn map_option<F: FnOnce(String) -> String>(opt: Option<String>, f: F) -> Option<String> {
    let result = f(opt.unwrap_or_default());
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

impl VirtualDirectoryPath {
    /// Converts a virtual directory path by manipulating the "sub folder".
    ///
    /// Returning an empty string means no sub_folder will be used in resulting path.
    ///
    /// Sub folder will be modified as follows:
    ///
    /// - LocalFolder: will see the entire path
    /// - others: will see the path inside the archive or empty string if none.
    pub fn map_sub_folder<F: FnOnce(String) -> String>(self, f: F) -> VirtualDirectoryPath {
        match self {
            LocalFolder { path } => LocalFolder { path: f(path) },
            LocalArchive { path, sub_folder } => LocalArchive {
                path,
                sub_folder: map_option(sub_folder, f),
            },
            RemoteArchive { url, sub_folder } => RemoteArchive {
                url,
                sub_folder: map_option(sub_folder, f),
            },
            GitRepo {
                url,
                refspec,
                sub_folder,
            } => GitRepo {
                url,
                refspec,
                sub_folder: map_option(sub_folder, f),
            },
        }
    }
}

impl TryFrom<String> for VirtualDirectoryPath {
    type Error = Error;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl TryFrom<&str> for VirtualDirectoryPath {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<VirtualDirectoryPath> for String {
    fn from(path: VirtualDirectoryPath) -> Self {
        path.to_string()
    }
}

impl FromStr for VirtualDirectoryPath {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let captures = REGISTRY_REGEX
            .captures(s)
            .ok_or(Error::InvalidRegistryPath {
                path: s.to_owned(),
                error: "Invalid registry path".to_owned(),
            })?;
        let source = captures
            .name("source")
            .ok_or(Error::InvalidRegistryPath {
                path: s.to_owned(),
                error: "Invalid virtual directory path. No local path or URL found".to_owned(),
            })?
            .as_str();
        let refspec = captures.name("refspec").map(|m| m.as_str().to_owned());
        let sub_folder = captures.name("sub_folder").map(|m| m.as_str().to_owned());

        if source.starts_with("http://") || source.starts_with("https://") {
            if source.ends_with(".zip") || source.ends_with(".tar.gz") {
                Ok(Self::RemoteArchive {
                    url: source.to_owned(),
                    sub_folder,
                })
            } else {
                Ok(Self::GitRepo {
                    url: source.to_owned(),
                    refspec,
                    sub_folder,
                })
            }
        } else if source.ends_with(".zip") || source.ends_with(".tar.gz") {
            Ok(Self::LocalArchive {
                path: source.to_owned(),
                sub_folder,
            })
        } else {
            Ok(Self::LocalFolder {
                path: source.to_owned(),
            })
        }
    }
}

impl Display for VirtualDirectoryPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LocalFolder { path } => write!(f, "{path}"),
            LocalArchive { path, sub_folder } => {
                if let Some(sub_folder) = sub_folder {
                    write!(f, "{path}[{sub_folder}]")
                } else {
                    write!(f, "{path}")
                }
            }
            RemoteArchive { url, sub_folder } => {
                if let Some(sub_folder) = sub_folder {
                    write!(f, "{url}[{sub_folder}]")
                } else {
                    write!(f, "{url}")
                }
            }
            GitRepo {
                url,
                refspec,
                sub_folder,
            } => match (refspec, sub_folder) {
                (Some(refspec), Some(folder)) => write!(f, "{url}@{refspec}[{folder}]"),
                (Some(refspec), None) => write!(f, "{url}@{refspec}"),
                (None, Some(folder)) => write!(f, "{url}[{folder}]"),
                (None, None) => write!(f, "{url}"),
            },
        }
    }
}
