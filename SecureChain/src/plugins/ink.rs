//! Ink! plugin for smart contract analysis
//! 
//! This plugin provides analysis capabilities for Ink! smart contracts
//! used on Polkadot and Substrate-based blockchains.

use anyhow::Result;
use std::process::Command;

use crate::core::parser::ParsedContract;
use crate::plugins::BlockchainPlugin;
use crate::report::vulnerability::{Vulnerability, VulnerabilityCategory};

/// Ink! plugin for analyzing Ink! smart contracts
pub struct InkPlugin {
    tools: Vec<&'static str>,
}

impl InkPlugin {
    /// Create a new Ink! plugin
    pub fn new() -> Self {
        Self {
            tools: vec!["cargo", "cargo-contract", "substrate", "ink-analyzer"],
        }
    }

    /// Check if Cargo is available
    pub fn is_cargo_available(&self) -> bool {
        Command::new("cargo")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Check if cargo-contract is available
    pub fn is_cargo_contract_available(&self) -> bool {
        Command::new("cargo")
            .arg("contract")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Run Ink!-specific analysis
    fn run_ink_analysis(&self, contract: &ParsedContract) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Check for Ink!-specific patterns
        vulnerabilities.extend(self.check_ink_attributes(contract)?);
        vulnerabilities.extend(self.check_storage_patterns(contract)?);
        vulnerabilities.extend(self.check_message_patterns(contract)?);
        vulnerabilities.extend(self.check_event_patterns(contract)?);

        Ok(vulnerabilities)
    }

    /// Check Ink! attributes usage
    fn check_ink_attributes(&self, contract: &ParsedContract) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Check for proper contract attribute
        if !contract.source_code.contains("#[ink::contract]") {
            vulnerabilities.push(Vulnerability {
                id: uuid::Uuid::new_v4().to_string(),
                title: "Missing Ink Contract Attribute".to_string(),
                description: "Ink! contracts must have the #[ink::contract] attribute.".to_string(),
                severity: "High".to_string(),
                category: VulnerabilityCategory::CodeQuality,
                file_path: contract.name.clone(),
                line_number: None,
                code_snippet: None,
                recommendation: Some("Add #[ink::contract] attribute to the contract module.".to_string()),
                references: vec!["https://ink.substrate.io/macros-attributes/contract/".to_string()],
                cwe_id: None,
                tool: "Ink Plugin".to_string(),
                confidence: 0.9,
            });
        }

        // Check for storage struct
        if contract.source_code.contains("#[ink::contract]") && !contract.source_code.contains("#[ink(storage)]") {
            vulnerabilities.push(Vulnerability {
                id: uuid::Uuid::new_v4().to_string(),
                title: "Missing Storage Struct".to_string(),
                description: "Ink! contracts must have a storage struct with #[ink(storage)] attribute.".to_string(),
                severity: "High".to_string(),
                category: VulnerabilityCategory::CodeQuality,
                file_path: contract.name.clone(),
                line_number: None,
                code_snippet: None,
                recommendation: Some("Define a storage struct with #[ink(storage)] attribute.".to_string()),
                references: vec!["https://ink.substrate.io/macros-attributes/storage/".to_string()],
                cwe_id: None,
                tool: "Ink Plugin".to_string(),
                confidence: 0.9,
            });
        }

        // Check for constructor
        if contract.source_code.contains("#[ink::contract]") && !contract.source_code.contains("#[ink(constructor)]") {
            vulnerabilities.push(Vulnerability {
                id: uuid::Uuid::new_v4().to_string(),
                title: "Missing Constructor".to_string(),
                description: "Ink! contracts should have at least one constructor.".to_string(),
                severity: "Medium".to_string(),
                category: VulnerabilityCategory::CodeQuality,
                file_path: contract.name.clone(),
                line_number: None,
                code_snippet: None,
                recommendation: Some("Add a constructor with #[ink(constructor)] attribute.".to_string()),
                references: vec!["https://ink.substrate.io/macros-attributes/constructor/".to_string()],
                cwe_id: None,
                tool: "Ink Plugin".to_string(),
                confidence: 0.7,
            });
        }

        Ok(vulnerabilities)
    }

    /// Check storage patterns
    fn check_storage_patterns(&self, contract: &ParsedContract) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Check for proper storage access
        if contract.source_code.contains("self.") && !contract.source_code.contains("&mut self") {
            vulnerabilities.push(Vulnerability {
                id: uuid::Uuid::new_v4().to_string(),
                title: "Immutable Storage Access".to_string(),
                description: "Storage modifications require mutable reference to self.".to_string(),
                severity: "Medium".to_string(),
                category: VulnerabilityCategory::CodeQuality,
                file_path: contract.name.clone(),
                line_number: None,
                code_snippet: None,
                recommendation: Some("Use &mut self parameter for functions that modify storage.".to_string()),
                references: vec!["https://ink.substrate.io/basics/storing-values/".to_string()],
                cwe_id: None,
                tool: "Ink Plugin".to_string(),
                confidence: 0.6,
            });
        }

        // Check for storage mapping usage
        if contract.source_code.contains("Mapping") && !contract.source_code.contains("use ink::storage::Mapping") {
            vulnerabilities.push(Vulnerability {
                id: uuid::Uuid::new_v4().to_string(),
                title: "Missing Mapping Import".to_string(),
                description: "Mapping usage requires proper import.".to_string(),
                severity: "Medium".to_string(),
                category: VulnerabilityCategory::CodeQuality,
                file_path: contract.name.clone(),
                line_number: None,
                code_snippet: None,
                recommendation: Some("Add 'use ink::storage::Mapping;' import.".to_string()),
                references: vec!["https://ink.substrate.io/datastructures/mapping/".to_string()],
                cwe_id: None,
                tool: "Ink Plugin".to_string(),
                confidence: 0.8,
            });
        }

        Ok(vulnerabilities)
    }

    /// Check message patterns
    fn check_message_patterns(&self, contract: &ParsedContract) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Check for public messages without proper access control
        if contract.source_code.contains("#[ink(message)]") && !contract.source_code.contains("caller") {
            vulnerabilities.push(Vulnerability {
                id: uuid::Uuid::new_v4().to_string(),
                title: "Message Without Access Control".to_string(),
                description: "Public messages should implement proper access control.".to_string(),
                severity: "High".to_string(),
                category: VulnerabilityCategory::AccessControl,
                file_path: contract.name.clone(),
                line_number: None,
                code_snippet: None,
                recommendation: Some("Implement caller validation using self.env().caller().".to_string()),
                references: vec!["https://ink.substrate.io/basics/contract-calls/".to_string()],
                cwe_id: Some("CWE-862".to_string()),
                tool: "Ink Plugin".to_string(),
                confidence: 0.7,
            });
        }

        // Check for payable messages
        if contract.source_code.contains("#[ink(message, payable)]") && !contract.source_code.contains("transferred_value") {
            vulnerabilities.push(Vulnerability {
                id: uuid::Uuid::new_v4().to_string(),
                title: "Payable Message Without Value Check".to_string(),
                description: "Payable messages should check transferred value.".to_string(),
                severity: "Medium".to_string(),
                category: VulnerabilityCategory::CodeQuality,
                file_path: contract.name.clone(),
                line_number: None,
                code_snippet: None,
                recommendation: Some("Use self.env().transferred_value() to check payment amount.".to_string()),
                references: vec!["https://ink.substrate.io/basics/payable/".to_string()],
                cwe_id: None,
                tool: "Ink Plugin".to_string(),
                confidence: 0.6,
            });
        }

        // Check for proper error handling
        if contract.source_code.contains("#[ink(message)]") && !contract.source_code.contains("Result") {
            vulnerabilities.push(Vulnerability {
                id: uuid::Uuid::new_v4().to_string(),
                title: "Message Without Error Handling".to_string(),
                description: "Messages should use Result type for proper error handling.".to_string(),
                severity: "Low".to_string(),
                category: VulnerabilityCategory::CodeQuality,
                file_path: contract.name.clone(),
                line_number: None,
                code_snippet: None,
                recommendation: Some("Use Result return type for fallible operations.".to_string()),
                references: vec!["https://ink.substrate.io/basics/contract-calls/".to_string()],
                cwe_id: None,
                tool: "Ink Plugin".to_string(),
                confidence: 0.5,
            });
        }

        Ok(vulnerabilities)
    }

    /// Check event patterns
    fn check_event_patterns(&self, contract: &ParsedContract) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Check for event definitions
        if contract.source_code.contains("#[ink(event)]") {
            // Check for indexed fields
            if !contract.source_code.contains("#[ink(topic)]") {
                vulnerabilities.push(Vulnerability {
                    id: uuid::Uuid::new_v4().to_string(),
                    title: "Event Without Indexed Fields".to_string(),
                    description: "Events should have indexed fields for efficient querying.".to_string(),
                    severity: "Low".to_string(),
                    category: VulnerabilityCategory::CodeQuality,
                    file_path: contract.name.clone(),
                    line_number: None,
                    code_snippet: None,
                    recommendation: Some("Add #[ink(topic)] attribute to important event fields.".to_string()),
                    references: vec!["https://ink.substrate.io/basics/events/".to_string()],
                    cwe_id: None,
                    tool: "Ink Plugin".to_string(),
                    confidence: 0.4,
                });
            }
        }

        // Check for event emission
        if contract.source_code.contains("#[ink(event)]") && !contract.source_code.contains("emit_event") {
            vulnerabilities.push(Vulnerability {
                id: uuid::Uuid::new_v4().to_string(),
                title: "Event Defined But Not Emitted".to_string(),
                description: "Defined events should be emitted in the contract.".to_string(),
                severity: "Info".to_string(),
                category: VulnerabilityCategory::CodeQuality,
                file_path: contract.name.clone(),
                line_number: None,
                code_snippet: None,
                recommendation: Some("Use self.env().emit_event() to emit events.".to_string()),
                references: vec!["https://ink.substrate.io/basics/events/".to_string()],
                cwe_id: None,
                tool: "Ink Plugin".to_string(),
                confidence: 0.3,
            });
        }

        Ok(vulnerabilities)
    }

    /// Check for Ink!-specific best practices
    fn check_ink_best_practices(&self, contract: &ParsedContract) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Check for proper error types
        if contract.source_code.contains("Result") && !contract.source_code.contains("enum") {
            vulnerabilities.push(Vulnerability {
                id: uuid::Uuid::new_v4().to_string(),
                title: "Consider Custom Error Types".to_string(),
                description: "Define custom error enums for better error handling.".to_string(),
                severity: "Info".to_string(),
                category: VulnerabilityCategory::CodeQuality,
                file_path: contract.name.clone(),
                line_number: None,
                code_snippet: None,
                recommendation: Some("Define custom error enum types for specific error conditions.".to_string()),
                references: vec!["https://ink.substrate.io/basics/contract-calls/".to_string()],
                cwe_id: None,
                tool: "Ink Plugin".to_string(),
                confidence: 0.3,
            });
        }

        // Check for proper testing
        if contract.source_code.contains("#[ink::contract]") && !contract.source_code.contains("#[cfg(test)]") {
            vulnerabilities.push(Vulnerability {
                id: uuid::Uuid::new_v4().to_string(),
                title: "Missing Unit Tests".to_string(),
                description: "Ink! contracts should include unit tests.".to_string(),
                severity: "Low".to_string(),
                category: VulnerabilityCategory::CodeQuality,
                file_path: contract.name.clone(),
                line_number: None,
                code_snippet: None,
                recommendation: Some("Add unit tests with #[cfg(test)] module.".to_string()),
                references: vec!["https://ink.substrate.io/basics/contract-testing/".to_string()],
                cwe_id: None,
                tool: "Ink Plugin".to_string(),
                confidence: 0.5,
            });
        }

        // Check for overflow protection
        if contract.source_code.contains("u8") || contract.source_code.contains("u32") || contract.source_code.contains("u64") {
            if !contract.source_code.contains("checked_add") && !contract.source_code.contains("saturating_add") {
                vulnerabilities.push(Vulnerability {
                    id: uuid::Uuid::new_v4().to_string(),
                    title: "Potential Integer Overflow".to_string(),
                    description: "Consider using checked arithmetic operations.".to_string(),
                    severity: "Medium".to_string(),
                    category: VulnerabilityCategory::IntegerOverflow,
                    file_path: contract.name.clone(),
                    line_number: None,
                    code_snippet: None,
                    recommendation: Some("Use checked_add, saturating_add, or similar safe arithmetic operations.".to_string()),
                    references: vec!["https://doc.rust-lang.org/std/primitive.u32.html#method.checked_add".to_string()],
                    cwe_id: Some("CWE-190".to_string()),
                    tool: "Ink Plugin".to_string(),
                    confidence: 0.6,
                });
            }
        }

        Ok(vulnerabilities)
    }
}

impl BlockchainPlugin for InkPlugin {
    fn name(&self) -> &'static str {
        "Ink!"
    }

    fn supported_languages(&self) -> Vec<&'static str> {
        vec!["ink", "rust"]
    }

    fn analyze_contract(&self, contract: &ParsedContract) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Run Ink!-specific analysis
        vulnerabilities.extend(self.run_ink_analysis(contract)?);
        vulnerabilities.extend(self.check_ink_best_practices(contract)?);

        Ok(vulnerabilities)
    }

    fn validate_contract(&self, contract: &ParsedContract) -> Result<bool> {
        // Basic validation for Ink! contracts
        if contract.source_code.is_empty() {
            return Ok(false);
        }

        // Check for Ink!-specific syntax
        if !contract.source_code.contains("#[ink::contract]") && !contract.source_code.contains("use ink") {
            return Ok(false);
        }

        Ok(true)
    }

    fn get_analysis_tools(&self) -> Vec<&'static str> {
        self.tools.clone()
    }
}

impl Default for InkPlugin {
    fn default() -> Self {
        Self::new()
    }
}