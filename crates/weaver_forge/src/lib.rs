// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

#[cfg(feature = "codegen")]
use std::borrow::Cow;
use std::collections::BTreeMap;
#[cfg(feature = "codegen")]
use std::ffi::OsString;
use std::fmt::{Debug, Display, Formatter};
use std::path::{Path, PathBuf};
#[cfg(feature = "codegen")]
use std::sync::{Arc, Mutex};
use std::{fmt, fs};

#[cfg(feature = "codegen")]
use minijinja::syntax::SyntaxConfig;
#[cfg(feature = "codegen")]
use minijinja::value::{from_args, Enumerator, Object};
#[cfg(feature = "codegen")]
use minijinja::{Environment, ErrorKind, State, Value};
#[cfg(feature = "codegen")]
use rayon::iter::IntoParallelIterator;
#[cfg(feature = "codegen")]
use rayon::iter::ParallelIterator;
use serde::Serialize;

use error::Error;
#[cfg(feature = "codegen")]
use error::Error::{
    ContextSerializationFailed, InvalidTemplateFile, TemplateEvaluationFailed,
    WriteGeneratedCodeFailed,
};
#[cfg(feature = "codegen")]
use weaver_common::error::handle_errors;
#[cfg(feature = "codegen")]
use weaver_common::log_success;

#[cfg(feature = "codegen")]
use crate::config::{ApplicationMode, AutoEscapeMode, Params, TemplateConfig, WeaverConfig};
#[cfg(feature = "codegen")]
use crate::debug::error_summary;
#[cfg(feature = "codegen")]
use crate::error::Error::{InvalidConfigFile, InvalidFilePath};
#[cfg(feature = "codegen")]
use crate::extensions::{ansi, case, code, otel, util};
#[cfg(feature = "codegen")]
use crate::file_loader::FileLoader;
#[cfg(feature = "codegen")]
use crate::filter::Filter;
#[cfg(feature = "codegen")]
use crate::registry::{ResolvedGroup, ResolvedRegistry};

#[cfg(feature = "codegen")]
pub mod config;
pub mod debug;
pub mod error;
#[cfg(feature = "codegen")]
pub mod extensions;
#[cfg(feature = "codegen")]
pub mod file_loader;
#[cfg(feature = "codegen")]
mod filter;
#[cfg(feature = "codegen")]
mod formats;
pub mod jq;
#[cfg(feature = "codegen")]
pub mod output_processor;
pub mod registry;
pub mod v2;

#[cfg(feature = "codegen")]
pub use output_processor::{OutputProcessor, OutputTarget};

/// Name of the Weaver configuration file.
pub const WEAVER_YAML: &str = "weaver.yaml";

/// Default jq filter for the semantic convention registry.
pub const SEMCONV_JQ: &str = include_str!("../../../defaults/jq/semconv.jq");

// Definition of the Jinja syntax delimiters

/// Constant defining the start of a Jinja block.
pub const BLOCK_START: &str = "{%";

/// Constant defining the end of a Jinja block.
pub const BLOCK_END: &str = "%}";

/// Constant defining the start of a Jinja variable.
pub const VARIABLE_START: &str = "{{";

/// Constant defining the end of a Jinja variable.
pub const VARIABLE_END: &str = "}}";

/// Constant defining the start of a Jinja comment.
pub const COMMENT_START: &str = "{#";

/// Constant defining the end of a Jinja comment.
pub const COMMEND_END: &str = "#}";


// Template engine and code generation — gated behind "codegen" feature.
#[cfg(feature = "codegen")]
mod codegen;
#[cfg(feature = "codegen")]
pub use codegen::*;
