//! Move language plugin for smart contract analysis
//! 
//! This plugin provides analysis capabilities for Move smart contracts
//! used on blockchains like Aptos, Sui, and Diem.

use anyhow::{anyhow, Result};
use std::process::Command;

use crate::core::parser::ParsedContract;
use crate::plugins::BlockchainPlugin;
use crate::report::vulnerability::{Vulnerability, VulnerabilityCategory};

/// Move plugin for analyzing Move smart contracts
pub struct MovePlugin {
    tools: Vec<&'static str>,
}

impl MovePlugin {
    /// Create a new Move plugin
    pub fn new() -> Self {
        Self {
            tools: vec!["move", "move-prover", "aptos", "sui"],
        }
    }

    /// Check if Move CLI is available
    pub fn is_move_available(&self) -> bool {
        Command::new("move")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Check if Move Prover is available
    pub fn is_move_prover_available(&self) -> bool {
        Command::new("move-prover")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Check if Aptos CLI is available
    pub fn is_aptos_available(&self) -> bool {
        Command::new("aptos")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Check if Sui CLI is available
    pub fn is_sui_available(&self) -> bool {
        Command::new("sui")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Run Move-specific analysis
    fn run_move_analysis(&self, contract: &ParsedContract) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Check for common Move anti-patterns
        vulnerabilities.extend(self.check_resource_safety(contract)?);
        vulnerabilities.extend(self.check_capability_patterns(contract)?);
        vulnerabilities.extend(self.check_abort_conditions(contract)?);
        vulnerabilities.extend(self.check_global_storage_access(contract)?);

        Ok(vulnerabilities)
    }

    /// Check resource safety patterns
    fn check_resource_safety(&self, contract: &ParsedContract) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Check for proper resource handling
        if contract.source_code.contains("move_from") && !contract.source_code.contains("exists<") {
            vulnerabilities.push(Vulnerability {
                id: uuid::Uuid::new_v4().to_string(),
                title: "Unchecked Resource Access".to_string(),
                description: "Resource is being moved without checking if it exists first.".to_string(),
                severity: "High".to_string(),
                category: VulnerabilityCategory::AccessControl,
                file_path: contract.name.clone(),
                line_number: None,
                code_snippet: None,
                recommendation: Some("Always check resource existence with exists<T>() before using move_from<T>().".to_string()),
                references: vec!["https://move-language.github.io/move/structs-and-resources.html".to_string()],
                cwe_id: Some("CWE-476".to_string()),
                tool: "Move Plugin".to_string(),
                confidence: 0.8,
            });
        }

        // Check for resource leaks
        if contract.source_code.contains("move_to") && !contract.source_code.contains("move_from") {
            vulnerabilities.push(Vulnerability {
                id: uuid::Uuid::new_v4().to_string(),
                title: "Potential Resource Leak".to_string(),
                description: "Resources are being created but never consumed, potentially leading to storage bloat.".to_string(),
                severity: "Medium".to_string(),
                category: VulnerabilityCategory::CodeQuality,
                file_path: contract.name.clone(),
                line_number: None,
                code_snippet: None,
                recommendation: Some("Ensure all resources have proper cleanup mechanisms.".to_string()),
                references: vec!["https://move-language.github.io/move/structs-and-resources.html".to_string()],
                cwe_id: None,
                tool: "Move Plugin".to_string(),
                confidence: 0.6,
            });
        }

        Ok(vulnerabilities)
    }

    /// Check capability patterns
    fn check_capability_patterns(&self, contract: &ParsedContract) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Check for proper capability usage
        if contract.source_code.contains("capability") {
            // Look for capability creation without proper access control
            if !contract.source_code.contains("acquires") && contract.source_code.contains("&signer") {
                vulnerabilities.push(Vulnerability {
                    id: uuid::Uuid::new_v4().to_string(),
                    title: "Improper Capability Management".to_string(),
                    description: "Capability is being used without proper signer validation.".to_string(),
                    severity: "High".to_string(),
                    category: VulnerabilityCategory::AccessControl,
                    file_path: contract.name.clone(),
                    line_number: None,
                    code_snippet: None,
                    recommendation: Some("Implement proper signer validation and capability checking.".to_string()),
                    references: vec!["https://aptos.dev/concepts/accounts/".to_string()],
                    cwe_id: Some("CWE-863".to_string()),
                    tool: "Move Plugin".to_string(),
                    confidence: 0.7,
                });
            }
        }

        Ok(vulnerabilities)
    }

    /// Check abort conditions
    fn check_abort_conditions(&self, contract: &ParsedContract) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Check for magic numbers in abort conditions
        let abort_pattern = regex::Regex::new(r"abort\s+(\d+)").unwrap();
        if let Some(captures) = abort_pattern.captures(&contract.source_code) {
            if let Some(error_code) = captures.get(1) {
                let code = error_code.as_str();
                if code.parse::<u32>().unwrap_or(0) > 100 {
                    vulnerabilities.push(Vulnerability {
                        id: uuid::Uuid::new_v4().to_string(),
                        title: "Magic Number in Abort".to_string(),
                        description: "Using magic numbers in abort conditions makes debugging difficult.".to_string(),
                        severity: "Low".to_string(),
                        category: VulnerabilityCategory::CodeQuality,
                        file_path: contract.name.clone(),
                        line_number: None,
                        code_snippet: Some(format!("abort {}", code)),
                        recommendation: Some("Define error constants for abort codes to improve readability.".to_string()),
                        references: vec!["https://move-language.github.io/move/abort-and-assert.html".to_string()],
                        cwe_id: None,
                        tool: "Move Plugin".to_string(),
                        confidence: 0.5,
                    });
                }
            }
        }

        Ok(vulnerabilities)
    }

    /// Check global storage access patterns
    fn check_global_storage_access(&self, contract: &ParsedContract) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Check for unsafe global storage operations
        if contract.source_code.contains("borrow_global_mut") {
            vulnerabilities.push(Vulnerability {
                id: uuid::Uuid::new_v4().to_string(),
                title: "Mutable Global Storage Access".to_string(),
                description: "Using mutable global storage access can lead to reentrancy-like issues.".to_string(),
                severity: "Medium".to_string(),
                category: VulnerabilityCategory::Reentrancy,
                file_path: contract.name.clone(),
                line_number: None,
                code_snippet: None,
                recommendation: Some("Consider using immutable references or implementing proper access patterns.".to_string()),
                references: vec!["https://move-language.github.io/move/global-storage-operators.html".to_string()],
                cwe_id: Some("CWE-362".to_string()),
                tool: "Move Plugin".to_string(),
                confidence: 0.6,
            });
        }

        // Check for missing acquires declarations
        if contract.source_code.contains("borrow_global") && !contract.source_code.contains("acquires") {
            vulnerabilities.push(Vulnerability {
                id: uuid::Uuid::new_v4().to_string(),
                title: "Missing Acquires Declaration".to_string(),
                description: "Function uses global storage but doesn't declare acquires.".to_string(),
                severity: "High".to_string(),
                category: VulnerabilityCategory::CodeQuality,
                file_path: contract.name.clone(),
                line_number: None,
                code_snippet: None,
                recommendation: Some("Add proper acquires declarations to functions that access global storage.".to_string()),
                references: vec!["https://move-language.github.io/move/global-storage-operators.html".to_string()],
                cwe_id: None,
                tool: "Move Plugin".to_string(),
                confidence: 0.9,
            });
        }

        Ok(vulnerabilities)
    }

    /// Check for Move-specific best practices
    fn check_move_best_practices(&self, contract: &ParsedContract) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Check for proper module structure
        if !contract.source_code.contains("module") {
            vulnerabilities.push(Vulnerability {
                id: uuid::Uuid::new_v4().to_string(),
                title: "Missing Module Declaration".to_string(),
                description: "Move code should be organized in modules.".to_string(),
                severity: "Medium".to_string(),
                category: VulnerabilityCategory::CodeQuality,
                file_path: contract.name.clone(),
                line_number: None,
                code_snippet: None,
                recommendation: Some("Organize code into proper Move modules.".to_string()),
                references: vec!["https://move-language.github.io/move/modules-and-scripts.html".to_string()],
                cwe_id: None,
                tool: "Move Plugin".to_string(),
                confidence: 0.8,
            });
        }

        // Check for proper visibility modifiers
        if contract.source_code.contains("public fun") && !contract.source_code.contains("public(friend)") {
            vulnerabilities.push(Vulnerability {
                id: uuid::Uuid::new_v4().to_string(),
                title: "Overly Permissive Function Visibility".to_string(),
                description: "Functions are public without friend restrictions.".to_string(),
                severity: "Low".to_string(),
                category: VulnerabilityCategory::AccessControl,
                file_path: contract.name.clone(),
                line_number: None,
                code_snippet: None,
                recommendation: Some("Consider using public(friend) or public(script) for better access control.".to_string()),
                references: vec!["https://move-language.github.io/move/functions.html".to_string()],
                cwe_id: Some("CWE-732".to_string()),
                tool: "Move Plugin".to_string(),
                confidence: 0.4,
            });
        }

        Ok(vulnerabilities)
    }
}

impl BlockchainPlugin for MovePlugin {
    fn name(&self) -> &'static str {
        "Move"
    }

    fn supported_languages(&self) -> Vec<&'static str> {
        vec!["move"]
    }

    fn analyze_contract(&self, contract: &ParsedContract) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Run Move-specific analysis
        vulnerabilities.extend(self.run_move_analysis(contract)?);
        vulnerabilities.extend(self.check_move_best_practices(contract)?);

        Ok(vulnerabilities)
    }

    fn validate_contract(&self, contract: &ParsedContract) -> Result<bool> {
        // Basic validation for Move contracts
        if contract.source_code.is_empty() {
            return Ok(false);
        }

        // Check for Move-specific syntax
        if !contract.source_code.contains("module") && !contract.source_code.contains("script") {
            return Ok(false);
        }

        // Check for basic Move constructs
        if !contract.source_code.contains("fun") && !contract.source_code.contains("struct") {
            return Ok(false);
        }

        Ok(true)
    }

    fn get_analysis_tools(&self) -> Vec<&'static str> {
        self.tools.clone()
    }
}

impl Default for MovePlugin {
    fn default() -> Self {
        Self::new()
    }
}
