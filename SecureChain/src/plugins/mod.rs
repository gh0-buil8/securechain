//! Plugin system for multi-language smart contract analysis
//! 
//! This module provides a pluggable architecture for supporting
//! different blockchain platforms and smart contract languages.

pub mod evm;
pub mod move_lang;
pub mod cairo;
pub mod ink;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::core::parser::ParsedContract;
use crate::report::vulnerability::Vulnerability;

/// Plugin trait for blockchain-specific analysis
pub trait BlockchainPlugin {
    fn name(&self) -> &'static str;
    fn supported_languages(&self) -> Vec<&'static str>;
    fn analyze_contract(&self, contract: &ParsedContract) -> Result<Vec<Vulnerability>>;
    fn validate_contract(&self, contract: &ParsedContract) -> Result<bool>;
    fn get_analysis_tools(&self) -> Vec<&'static str>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    pub name: String,
    pub version: String,
    pub description: String,
    pub supported_languages: Vec<String>,
    pub available_tools: Vec<String>,
    pub enabled: bool,
}

/// Plugin manager for coordinating different blockchain plugins
pub struct PluginManager {
    plugins: HashMap<String, Box<dyn BlockchainPlugin>>,
}

impl PluginManager {
    /// Create a new plugin manager
    pub fn new() -> Self {
        let mut plugins: HashMap<String, Box<dyn BlockchainPlugin>> = HashMap::new();
        
        // Register built-in plugins
        plugins.insert("evm".to_string(), Box::new(evm::EVMPlugin::new()));
        plugins.insert("move".to_string(), Box::new(move_lang::MovePlugin::new()));
        plugins.insert("cairo".to_string(), Box::new(cairo::CairoPlugin::new()));
        plugins.insert("ink".to_string(), Box::new(ink::InkPlugin::new()));

        Self { plugins }
    }

    /// Get available plugins
    pub fn get_available_plugins(&self) -> Vec<PluginInfo> {
        self.plugins
            .iter()
            .map(|(name, plugin)| PluginInfo {
                name: name.clone(),
                version: "0.1.0".to_string(),
                description: format!("Plugin for {} blockchain platform", plugin.name()),
                supported_languages: plugin.supported_languages().iter().map(|s| s.to_string()).collect(),
                available_tools: plugin.get_analysis_tools().iter().map(|s| s.to_string()).collect(),
                enabled: true,
            })
            .collect()
    }

    /// Get plugin by name
    pub fn get_plugin(&self, name: &str) -> Option<&Box<dyn BlockchainPlugin>> {
        self.plugins.get(name)
    }

    /// Analyze contract using appropriate plugin
    pub fn analyze_contract(&self, contract: &ParsedContract, target_platform: &str) -> Result<Vec<Vulnerability>> {
        if let Some(plugin) = self.plugins.get(target_platform) {
            plugin.analyze_contract(contract)
        } else {
            Err(anyhow::anyhow!("Plugin not found for platform: {}", target_platform))
        }
    }

    /// Validate contract using appropriate plugin
    pub fn validate_contract(&self, contract: &ParsedContract, target_platform: &str) -> Result<bool> {
        if let Some(plugin) = self.plugins.get(target_platform) {
            plugin.validate_contract(contract)
        } else {
            Err(anyhow::anyhow!("Plugin not found for platform: {}", target_platform))
        }
    }

    /// Check if a tool is available for a platform
    pub fn is_tool_available(&self, platform: &str, tool: &str) -> bool {
        if let Some(plugin) = self.plugins.get(platform) {
            plugin.get_analysis_tools().contains(&tool)
        } else {
            false
        }
    }
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}
