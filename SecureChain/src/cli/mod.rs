//! CLI module for BugForgeX
//! 
//! This module contains the command-line interface implementation,
//! including command parsing, validation, and execution.

pub mod commands;

pub use commands::{Cli, execute_command};
