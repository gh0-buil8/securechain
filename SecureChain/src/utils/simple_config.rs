//! Simplified configuration for BugForgeX
//! 
//! This module provides basic configuration management.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub log_level: String,
    pub output_dir: PathBuf,
    pub ai_backend: String,
    pub ai_enabled: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            log_level: "info".to_string(),
            output_dir: PathBuf::from("./output"),
            ai_backend: "local".to_string(),
            ai_enabled: false,
        }
    }
}

impl Config {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self::default())
    }
}