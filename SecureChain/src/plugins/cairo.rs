//! Cairo plugin for smart contract analysis
//! 
//! This plugin provides analysis capabilities for Cairo smart contracts
//! used on StarkNet and other Cairo-based blockchains.

use anyhow::{anyhow, Result};
use std::process::Command;

use crate::core::parser::ParsedContract;
use crate::plugins::BlockchainPlugin;
use crate::report::vulnerability::{Vulnerability, VulnerabilityCategory};

/// Cairo plugin for analyzing Cairo smart contracts
pub struct CairoPlugin {
    tools: Vec<&'static str>,
}

impl CairoPlugin {
    /// Create a new Cairo plugin
    pub fn new() -> Self {
        Self {
            tools: vec!["cairo-compile", "starknet-compile", "protostar", "scarb"],
        }
    }

    /// Check if Cairo compiler is available
    pub fn is_cairo_available(&self) -> bool {
        Command::new("cairo-compile")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Check if StarkNet compiler is available
    pub fn is_starknet_available(&self) -> bool {
        Command::new("starknet-compile")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Check if Protostar is available
    pub fn is_protostar_available(&self) -> bool {
        Command::new("protostar")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Run Cairo-specific analysis
    fn run_cairo_analysis(&self, contract: &ParsedContract) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Check for Cairo-specific patterns
        vulnerabilities.extend(self.check_felt_operations(contract)?);
        vulnerabilities.extend(self.check_storage_vars(contract)?);
        vulnerabilities.extend(self.check_external_functions(contract)?);
        vulnerabilities.extend(self.check_assert_usage(contract)?);

        Ok(vulnerabilities)
    }

    /// Check felt operations for potential issues
    fn check_felt_operations(&self, contract: &ParsedContract) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Check for unsafe felt arithmetic
        if contract.source_code.contains("felt") && contract.source_code.contains("*") {
            vulnerabilities.push(Vulnerability {
                id: uuid::Uuid::new_v4().to_string(),
                title: "Potential Felt Overflow".to_string(),
                description: "Felt operations can overflow without proper bounds checking.".to_string(),
                severity: "Medium".to_string(),
                category: VulnerabilityCategory::IntegerOverflow,
                file_path: contract.name.clone(),
                line_number: None,
                code_snippet: None,
                recommendation: Some("Use safe math operations or implement proper overflow checks for felt arithmetic.".to_string()),
                references: vec!["https://cairo-lang.org/docs/hello_cairo/intro.html".to_string()],
                cwe_id: Some("CWE-190".to_string()),
                tool: "Cairo Plugin".to_string(),
                confidence: 0.6,
            });
        }

        // Check for unchecked felt conversions
        if contract.source_code.contains("felt_to_uint256") || contract.source_code.contains("uint256_to_felt") {
            vulnerabilities.push(Vulnerability {
                id: uuid::Uuid::new_v4().to_string(),
                title: "Unchecked Felt Conversion".to_string(),
                description: "Felt conversions should be checked for validity.".to_string(),
                severity: "Low".to_string(),
                category: VulnerabilityCategory::CodeQuality,
                file_path: contract.name.clone(),
                line_number: None,
                code_snippet: None,
                recommendation: Some("Add validation for felt conversions to prevent unexpected behavior.".to_string()),
                references: vec!["https://cairo-lang.org/docs/".to_string()],
                cwe_id: None,
                tool: "Cairo Plugin".to_string(),
                confidence: 0.5,
            });
        }

        Ok(vulnerabilities)
    }

    /// Check storage variable usage
    fn check_storage_vars(&self, contract: &ParsedContract) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Check for proper storage variable declarations
        if contract.source_code.contains("@storage_var") {
            // Check if storage variables are properly initialized
            if !contract.source_code.contains("constructor") && !contract.source_code.contains("initializer") {
                vulnerabilities.push(Vulnerability {
                    id: uuid::Uuid::new_v4().to_string(),
                    title: "Uninitialized Storage Variables".to_string(),
                    description: "Storage variables should be properly initialized.".to_string(),
                    severity: "Medium".to_string(),
                    category: VulnerabilityCategory::CodeQuality,
                    file_path: contract.name.clone(),
                    line_number: None,
                    code_snippet: None,
                    recommendation: Some("Implement proper initialization for storage variables.".to_string()),
                    references: vec!["https://cairo-lang.org/docs/hello_starknet/intro.html".to_string()],
                    cwe_id: Some("CWE-665".to_string()),
                    tool: "Cairo Plugin".to_string(),
                    confidence: 0.7,
                });
            }
        }

        // Check for storage variable access patterns
        if contract.source_code.contains(".read()") && !contract.source_code.contains("assert") {
            vulnerabilities.push(Vulnerability {
                id: uuid::Uuid::new_v4().to_string(),
                title: "Unchecked Storage Access".to_string(),
                description: "Storage reads should be validated for expected values.".to_string(),
                severity: "Low".to_string(),
                category: VulnerabilityCategory::CodeQuality,
                file_path: contract.name.clone(),
                line_number: None,
                code_snippet: None,
                recommendation: Some("Add validation for storage reads when appropriate.".to_string()),
                references: vec!["https://cairo-lang.org/docs/hello_starknet/intro.html".to_string()],
                cwe_id: None,
                tool: "Cairo Plugin".to_string(),
                confidence: 0.4,
            });
        }

        Ok(vulnerabilities)
    }

    /// Check external function security
    fn check_external_functions(&self, contract: &ParsedContract) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Check for external functions without proper access control
        if contract.source_code.contains("@external") && !contract.source_code.contains("assert_only_owner") {
            vulnerabilities.push(Vulnerability {
                id: uuid::Uuid::new_v4().to_string(),
                title: "External Function Without Access Control".to_string(),
                description: "External functions should implement proper access control.".to_string(),
                severity: "High".to_string(),
                category: VulnerabilityCategory::AccessControl,
                file_path: contract.name.clone(),
                line_number: None,
                code_snippet: None,
                recommendation: Some("Implement access control mechanisms for external functions.".to_string()),
                references: vec!["https://cairo-lang.org/docs/hello_starknet/intro.html".to_string()],
                cwe_id: Some("CWE-862".to_string()),
                tool: "Cairo Plugin".to_string(),
                confidence: 0.8,
            });
        }

        // Check for reentrancy patterns
        if contract.source_code.contains("call_contract") && contract.source_code.contains("@storage_var") {
            vulnerabilities.push(Vulnerability {
                id: uuid::Uuid::new_v4().to_string(),
                title: "Potential Reentrancy".to_string(),
                description: "External calls combined with storage modifications can lead to reentrancy.".to_string(),
                severity: "High".to_string(),
                category: VulnerabilityCategory::Reentrancy,
                file_path: contract.name.clone(),
                line_number: None,
                code_snippet: None,
                recommendation: Some("Use checks-effects-interactions pattern or implement reentrancy guards.".to_string()),
                references: vec!["https://cairo-lang.org/docs/hello_starknet/intro.html".to_string()],
                cwe_id: Some("CWE-362".to_string()),
                tool: "Cairo Plugin".to_string(),
                confidence: 0.7,
            });
        }

        Ok(vulnerabilities)
    }

    /// Check assert usage patterns
    fn check_assert_usage(&self, contract: &ParsedContract) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Check for proper error handling
        if contract.source_code.contains("assert") {
            // Count assert statements
            let assert_count = contract.source_code.matches("assert").count();
            if assert_count > 10 {
                vulnerabilities.push(Vulnerability {
                    id: uuid::Uuid::new_v4().to_string(),
                    title: "Excessive Assert Usage".to_string(),
                    description: "Too many assert statements can make the contract expensive to execute.".to_string(),
                    severity: "Low".to_string(),
                    category: VulnerabilityCategory::CodeQuality,
                    file_path: contract.name.clone(),
                    line_number: None,
                    code_snippet: None,
                    recommendation: Some("Consider using more efficient error handling patterns.".to_string()),
                    references: vec!["https://cairo-lang.org/docs/".to_string()],
                    cwe_id: None,
                    tool: "Cairo Plugin".to_string(),
                    confidence: 0.5,
                });
            }
        }

        // Check for missing assertions in critical functions
        if contract.source_code.contains("@external") && !contract.source_code.contains("assert") {
            vulnerabilities.push(Vulnerability {
                id: uuid::Uuid::new_v4().to_string(),
                title: "Missing Input Validation".to_string(),
                description: "External functions should validate inputs using assertions.".to_string(),
                severity: "Medium".to_string(),
                category: VulnerabilityCategory::InputValidation,
                file_path: contract.name.clone(),
                line_number: None,
                code_snippet: None,
                recommendation: Some("Add input validation using assert statements.".to_string()),
                references: vec!["https://cairo-lang.org/docs/".to_string()],
                cwe_id: Some("CWE-20".to_string()),
                tool: "Cairo Plugin".to_string(),
                confidence: 0.6,
            });
        }

        Ok(vulnerabilities)
    }

    /// Check for Cairo-specific best practices
    fn check_cairo_best_practices(&self, contract: &ParsedContract) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Check for proper namespace usage
        if contract.source_code.contains("namespace") && contract.source_code.contains("from starkware.cairo.common") {
            vulnerabilities.push(Vulnerability {
                id: uuid::Uuid::new_v4().to_string(),
                title: "Namespace Best Practice".to_string(),
                description: "Using proper namespaces improves code organization.".to_string(),
                severity: "Info".to_string(),
                category: VulnerabilityCategory::CodeQuality,
                file_path: contract.name.clone(),
                line_number: None,
                code_snippet: None,
                recommendation: Some("Continue using proper namespace organization.".to_string()),
                references: vec!["https://cairo-lang.org/docs/".to_string()],
                cwe_id: None,
                tool: "Cairo Plugin".to_string(),
                confidence: 0.3,
            });
        }

        // Check for proper import usage
        if contract.source_code.contains("from starkware.cairo.common") && !contract.source_code.contains("alloc") {
            vulnerabilities.push(Vulnerability {
                id: uuid::Uuid::new_v4().to_string(),
                title: "Missing Memory Management".to_string(),
                description: "Consider if memory allocation functions are needed.".to_string(),
                severity: "Info".to_string(),
                category: VulnerabilityCategory::CodeQuality,
                file_path: contract.name.clone(),
                line_number: None,
                code_snippet: None,
                recommendation: Some("Review if memory allocation functions are needed for this contract.".to_string()),
                references: vec!["https://cairo-lang.org/docs/".to_string()],
                cwe_id: None,
                tool: "Cairo Plugin".to_string(),
                confidence: 0.2,
            });
        }

        Ok(vulnerabilities)
    }
}

impl BlockchainPlugin for CairoPlugin {
    fn name(&self) -> &'static str {
        "Cairo"
    }

    fn supported_languages(&self) -> Vec<&'static str> {
        vec!["cairo"]
    }

    fn analyze_contract(&self, contract: &ParsedContract) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Run Cairo-specific analysis
        vulnerabilities.extend(self.run_cairo_analysis(contract)?);
        vulnerabilities.extend(self.check_cairo_best_practices(contract)?);

        Ok(vulnerabilities)
    }

    fn validate_contract(&self, contract: &ParsedContract) -> Result<bool> {
        // Basic validation for Cairo contracts
        if contract.source_code.is_empty() {
            return Ok(false);
        }

        // Check for Cairo-specific syntax
        if !contract.source_code.contains("%lang starknet") && !contract.source_code.contains("from starkware.cairo.common") {
            return Ok(false);
        }

        Ok(true)
    }

    fn get_analysis_tools(&self) -> Vec<&'static str> {
        self.tools.clone()
    }
}

impl Default for CairoPlugin {
    fn default() -> Self {
        Self::new()
    }
}
