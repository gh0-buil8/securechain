//! Error handling utilities for BugForgeX
//! 
//! This module provides custom error types and error handling
//! utilities for the application.

use anyhow;
use reqwest;
use serde_json;

use thiserror::Error;
use toml;

/// Main error type for BugForgeX
#[derive(Error, Debug)]
pub enum BugForgeXError {
    /// IO errors
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization/deserialization errors
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// TOML parsing errors
    #[error("TOML error: {0}")]
    Toml(#[from] toml::de::Error),

    /// HTTP request errors
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// Regex compilation errors
    #[error("Regex error: {0}")]
    Regex(#[from] regex::Error),

    /// Configuration errors
    #[error("Configuration error: {message}")]
    Config { message: String },

    /// Plugin errors
    #[error("Plugin error: {plugin}: {message}")]
    Plugin { plugin: String, message: String },

    /// Analysis errors
    #[error("Analysis error: {message}")]
    Analysis { message: String },

    /// Contract fetching errors
    #[error("Contract fetch error: {message}")]
    ContractFetch { message: String },

    /// Contract parsing errors
    #[error("Contract parse error: {message}")]
    ContractParse { message: String },

    /// AI assistant errors
    #[error("AI assistant error: {message}")]
    AiAssistant { message: String },

    /// Report generation errors
    #[error("Report generation error: {message}")]
    ReportGeneration { message: String },

    /// Tool execution errors
    #[error("Tool execution error: {tool}: {message}")]
    ToolExecution { tool: String, message: String },

    /// Network errors
    #[error("Network error: {message}")]
    Network { message: String },

    /// Authentication errors
    #[error("Authentication error: {message}")]
    Authentication { message: String },

    /// Rate limiting errors
    #[error("Rate limit exceeded: {message}")]
    RateLimit { message: String },

    /// Generic errors
    #[error("Error: {message}")]
    Generic { message: String },
}


impl BugForgeXError {
    /// Create a new configuration error
    pub fn config(message: impl Into<String>) -> Self {
        BugForgeXError::Config {
            message: message.into(),
        }
    }

    /// Create a new plugin error
    pub fn plugin(plugin: impl Into<String>, message: impl Into<String>) -> Self {
        BugForgeXError::Plugin {
            plugin: plugin.into(),
            message: message.into(),
        }
    }

    /// Create a new analysis error
    pub fn analysis(message: impl Into<String>) -> Self {
        BugForgeXError::Analysis {
            message: message.into(),
        }
    }

    /// Create a new contract fetch error
    pub fn contract_fetch(message: impl Into<String>) -> Self {
        BugForgeXError::ContractFetch {
            message: message.into(),
        }
    }

    /// Create a new contract parse error
    pub fn contract_parse(message: impl Into<String>) -> Self {
        BugForgeXError::ContractParse {
            message: message.into(),
        }
    }

    /// Create a new AI assistant error
    pub fn ai_assistant(message: impl Into<String>) -> Self {
        BugForgeXError::AiAssistant {
            message: message.into(),
        }
    }

    /// Create a new report generation error
    pub fn report_generation(message: impl Into<String>) -> Self {
        BugForgeXError::ReportGeneration {
            message: message.into(),
        }
    }

    /// Create a new tool execution error
    pub fn tool_execution(tool: impl Into<String>, message: impl Into<String>) -> Self {
        BugForgeXError::ToolExecution {
            tool: tool.into(),
            message: message.into(),
        }
    }

    /// Create a new network error
    pub fn network(message: impl Into<String>) -> Self {
        BugForgeXError::Network {
            message: message.into(),
        }
    }

    /// Create a new authentication error
    pub fn authentication(message: impl Into<String>) -> Self {
        BugForgeXError::Authentication {
            message: message.into(),
        }
    }

    /// Create a new rate limit error
    pub fn rate_limit(message: impl Into<String>) -> Self {
        BugForgeXError::RateLimit {
            message: message.into(),
        }
    }

    /// Create a new generic error
    pub fn generic(message: impl Into<String>) -> Self {
        BugForgeXError::Generic {
            message: message.into(),
        }
    }
}

/// Result type alias for BugForgeX operations
pub type Result<T> = std::result::Result<T, BugForgeXError>;

/// Error context trait for adding context to errors
pub trait ErrorContext<T> {
    fn context(self, message: &str) -> Result<T>;
    fn with_context<F>(self, f: F) -> Result<T>
    where
        F: FnOnce() -> String;
}

impl<T, E> ErrorContext<T> for std::result::Result<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn context(self, message: &str) -> Result<T> {
        self.map_err(|e| BugForgeXError::Generic {
            message: format!("{}: {}", message, e),
        })
    }

    fn with_context<F>(self, f: F) -> Result<T>
    where
        F: FnOnce() -> String,
    {
        self.map_err(|e| BugForgeXError::Generic {
            message: format!("{}: {}", f(), e),
        })
    }
}

/// Utility functions for error handling
pub mod utils {
    use super::*;

    /// Convert anyhow::Error to BugForgeXError
    pub fn from_anyhow(err: anyhow::Error) -> BugForgeXError {
        BugForgeXError::Generic {
            message: err.to_string(),
        }
    }

    /// Log and return an error
    pub fn log_error<T>(err: BugForgeXError) -> Result<T> {
        log::error!("{}", err);
        Err(err)
    }

    /// Log warning and continue
    pub fn log_warning(message: &str) {
        log::warn!("{}", message);
    }

    /// Check if error is retryable
    pub fn is_retryable_error(err: &BugForgeXError) -> bool {
        matches!(
            err,
            BugForgeXError::Network { .. } | BugForgeXError::RateLimit { .. } | BugForgeXError::Http(_)
        )
    }

    /// Get error category for metrics
    pub fn get_error_category(err: &BugForgeXError) -> &'static str {
        match err {
            BugForgeXError::Io(_) => "io",
            BugForgeXError::Json(_) => "serialization",
            BugForgeXError::Toml(_) => "config",
            BugForgeXError::Http(_) => "http",
            BugForgeXError::Regex(_) => "regex",
            BugForgeXError::Config { .. } => "config",
            BugForgeXError::Plugin { .. } => "plugin",
            BugForgeXError::Analysis { .. } => "analysis",
            BugForgeXError::ContractFetch { .. } => "fetch",
            BugForgeXError::ContractParse { .. } => "parse",
            BugForgeXError::AiAssistant { .. } => "ai",
            BugForgeXError::ReportGeneration { .. } => "report",
            BugForgeXError::ToolExecution { .. } => "tool",
            BugForgeXError::Network { .. } => "network",
            BugForgeXError::Authentication { .. } => "auth",
            BugForgeXError::RateLimit { .. } => "rate_limit",
            BugForgeXError::Generic { .. } => "generic",
        }
    }
}

/// Macro for creating quick errors
#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        $crate::utils::error::BugForgeXError::generic(format!($($arg)*))
    };
}

/// Macro for creating quick result errors
#[macro_export]
macro_rules! bail {
    ($($arg:tt)*) => {
        return Err($crate::error!($($arg)*));
    };
}

/// Macro for ensuring conditions
#[macro_export]
macro_rules! ensure {
    ($cond:expr, $($arg:tt)*) => {
        if !$cond {
            $crate::bail!($($arg)*);
        }
    };
}