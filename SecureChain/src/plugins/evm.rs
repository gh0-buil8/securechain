//! EVM (Ethereum Virtual Machine) plugin for smart contract analysis
//! 
//! This plugin provides analysis capabilities for Solidity smart contracts
//! running on EVM-compatible blockchains like Ethereum, Polygon, Arbitrum, etc.

use anyhow::Result;
use std::process::Command;
use tokio::process::Command as AsyncCommand;

use crate::core::parser::ParsedContract;
use crate::plugins::BlockchainPlugin;
use crate::report::vulnerability::{Vulnerability, VulnerabilityCategory};

/// EVM plugin for analyzing Solidity smart contracts
pub struct EVMPlugin {
    tools: Vec<&'static str>,
}

impl EVMPlugin {
    /// Create a new EVM plugin
    pub fn new() -> Self {
        Self {
            tools: vec!["slither", "mythril", "echidna", "foundry", "solhint"],
        }
    }

    /// Check if Slither is available
    pub fn is_slither_available(&self) -> bool {
        Command::new("slither")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Check if Mythril is available
    pub fn is_mythril_available(&self) -> bool {
        Command::new("myth")
            .arg("version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Check if Echidna is available
    pub fn is_echidna_available(&self) -> bool {
        Command::new("echidna-test")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Run Slither analysis
    async fn run_slither_analysis(&self, contract: &ParsedContract) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        if !self.is_slither_available() {
            log::warn!("Slither not available, skipping static analysis");
            return Ok(vulnerabilities);
        }

        // Create temporary file for analysis
        let temp_file = tempfile::NamedTempFile::new()?;
        std::fs::write(temp_file.path(), &contract.source_code)?;

        // Run Slither with JSON output
        let output = AsyncCommand::new("slither")
            .arg(temp_file.path())
            .arg("--json")
            .arg("-")
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            log::warn!("Slither analysis failed: {}", stderr);
            return Ok(vulnerabilities);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        vulnerabilities.extend(self.parse_slither_output(&stdout, contract)?);

        Ok(vulnerabilities)
    }

    /// Parse Slither JSON output
    fn parse_slither_output(&self, output: &str, contract: &ParsedContract) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Parse JSON output
        if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(output) {
            if let Some(results) = json_value.get("results") {
                if let Some(detectors) = results.get("detectors") {
                    if let Some(detector_array) = detectors.as_array() {
                        for detector in detector_array {
                            if let Some(vuln) = self.parse_slither_detector(detector, contract) {
                                vulnerabilities.push(vuln);
                            }
                        }
                    }
                }
            }
        }

        Ok(vulnerabilities)
    }

    /// Parse individual Slither detector result
    fn parse_slither_detector(&self, detector: &serde_json::Value, contract: &ParsedContract) -> Option<Vulnerability> {
        let check = detector.get("check")?.as_str()?;
        let impact = detector.get("impact")?.as_str()?;
        let confidence = detector.get("confidence")?.as_str()?;
        let description = detector.get("description")?.as_str()?;

        // Extract source mapping information
        let mut line_number = None;
        let mut code_snippet = None;

        if let Some(elements) = detector.get("elements") {
            if let Some(element_array) = elements.as_array() {
                if let Some(first_element) = element_array.first() {
                    if let Some(source_mapping) = first_element.get("source_mapping") {
                        if let Some(lines) = source_mapping.get("lines") {
                            if let Some(line_array) = lines.as_array() {
                                if let Some(line) = line_array.first() {
                                    line_number = line.as_u64().map(|l| l as usize);
                                }
                            }
                        }
                    }

                    // Extract code snippet
                    if let Some(source_mapping) = first_element.get("source_mapping") {
                        if let Some(starting_column) = source_mapping.get("starting_column") {
                            if let Some(ending_column) = source_mapping.get("ending_column") {
                                if let Some(line_num) = line_number {
                                    let lines: Vec<&str> = contract.source_code.lines().collect();
                                    if line_num > 0 && line_num <= lines.len() {
                                        let line_content = lines[line_num - 1];
                                        let start_col = starting_column.as_u64().unwrap_or(0) as usize;
                                        let end_col = ending_column.as_u64().unwrap_or(line_content.len() as u64) as usize;

                                        if start_col < line_content.len() && end_col <= line_content.len() {
                                            code_snippet = Some(line_content[start_col..end_col].to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Some(Vulnerability {
            id: uuid::Uuid::new_v4().to_string(),
            title: format!("Slither: {}", self.format_check_name(check)),
            description: description.to_string(),
            severity: self.map_slither_severity(impact),
            category: self.map_slither_category(check),
            file_path: contract.name.clone(),
            line_number,
            code_snippet,
            recommendation: Some(self.get_slither_recommendation(check)),
            references: vec![
                "https://github.com/crytic/slither".to_string(),
                format!("https://github.com/crytic/slither/wiki/Detector-Documentation#{}", check)
            ],
            cwe_id: self.get_cwe_id(check),
            tool: "Slither".to_string(),
            confidence: self.map_confidence(confidence),
        })
    }

    /// Format check name for display
    fn format_check_name(&self, check: &str) -> String {
        check.replace('-', " ")
            .split_whitespace()
            .map(|word| {
                let mut chars = word.chars();
                match chars.next() {
                    None => String::new(),
                    Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                }
            })
            .collect::<Vec<String>>()
            .join(" ")
    }

    /// Map Slither severity to standard severity
    fn map_slither_severity(&self, impact: &str) -> String {
        match impact.to_lowercase().as_str() {
            "high" => "High".to_string(),
            "medium" => "Medium".to_string(),
            "low" => "Low".to_string(),
            "informational" => "Info".to_string(),
            _ => "Medium".to_string(),
        }
    }

    /// Map Slither check to vulnerability category
    fn map_slither_category(&self, check: &str) -> VulnerabilityCategory {
        match check {
            "reentrancy-eth" | "reentrancy-no-eth" | "reentrancy-events" => VulnerabilityCategory::Reentrancy,
            "unchecked-transfer" | "unchecked-send" | "unchecked-lowlevel" => VulnerabilityCategory::UnhandledExceptions,
            "tx-origin" | "suicidal" | "arbitrary-send" => VulnerabilityCategory::AccessControl,
            "timestamp" | "weak-prng" => VulnerabilityCategory::TimestampDependence,
            "low-level-calls" | "assembly" => VulnerabilityCategory::LowLevelCalls,
            "integer-overflow" | "divide-by-zero" => VulnerabilityCategory::IntegerOverflow,
            "locked-ether" | "missing-zero-check" => VulnerabilityCategory::CodeQuality,
            "dos-" => VulnerabilityCategory::DenialOfService,
            _ => VulnerabilityCategory::Other,
        }
    }

    /// Get CWE ID for specific checks
    fn get_cwe_id(&self, check: &str) -> Option<String> {
        match check {
            "reentrancy-eth" | "reentrancy-no-eth" => Some("CWE-362".to_string()),
            "tx-origin" => Some("CWE-477".to_string()),
            "timestamp" => Some("CWE-330".to_string()),
            "unchecked-transfer" => Some("CWE-252".to_string()),
            "integer-overflow" => Some("CWE-190".to_string()),
            "divide-by-zero" => Some("CWE-369".to_string()),
            _ => None,
        }
    }

    /// Get recommendation for specific checks
    fn get_slither_recommendation(&self, check: &str) -> String {
        match check {
            "reentrancy-eth" | "reentrancy-no-eth" => {
                "Use the Checks-Effects-Interactions pattern or implement reentrancy guards using OpenZeppelin's ReentrancyGuard.".to_string()
            }
            "tx-origin" => {
                "Use msg.sender instead of tx.origin for authorization checks.".to_string()
            }
            "timestamp" => {
                "Avoid using block.timestamp for critical logic. Consider using block numbers or external oracles.".to_string()
            }
            "unchecked-transfer" => {
                "Check the return value of transfer operations or use SafeERC20 from OpenZeppelin.".to_string()
            }
            "integer-overflow" => {
                "Use SafeMath library or Solidity 0.8+ built-in overflow protection.".to_string()
            }
            "low-level-calls" => {
                "Avoid low-level calls when possible. If necessary, handle return values properly.".to_string()
            }
            "arbitrary-send" => {
                "Implement proper access controls to prevent unauthorized Ether transfers.".to_string()
            }
            _ => format!("Review and address the {} issue detected by Slither.", check),
        }
    }

    /// Map confidence string to numeric value
    fn map_confidence(&self, confidence: &str) -> f64 {
        match confidence.to_lowercase().as_str() {
            "high" => 0.9,
            "medium" => 0.7,
            "low" => 0.5,
            _ => 0.6,
        }
    }

    /// Run basic syntax and semantic checks
    fn run_basic_checks(&self, contract: &ParsedContract) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Check for common anti-patterns
        if contract.source_code.contains("tx.origin") {
            vulnerabilities.push(Vulnerability {
                id: uuid::Uuid::new_v4().to_string(),
                title: "Use of tx.origin".to_string(),
                description: "The contract uses tx.origin for authorization, which can be exploited in phishing attacks.".to_string(),
                severity: "High".to_string(),
                category: VulnerabilityCategory::AccessControl,
                file_path: contract.name.clone(),
                line_number: None,
                code_snippet: None,
                recommendation: Some("Use msg.sender instead of tx.origin for authorization checks.".to_string()),
                references: vec!["https://consensys.github.io/smart-contract-best-practices/recommendations/#avoid-using-txorigin".to_string()],
                cwe_id: Some("CWE-477".to_string()),
                tool: "EVM Plugin".to_string(),
                confidence: 0.9,
            });
        }

        // Check for deprecated functions
        if contract.source_code.contains("suicide(") || contract.source_code.contains("selfdestruct(") {
            vulnerabilities.push(Vulnerability {
                id: uuid::Uuid::new_v4().to_string(),
                title: "Use of selfdestruct/suicide".to_string(),
                description: "The contract uses selfdestruct which can lead to unexpected behavior.".to_string(),
                severity: "Medium".to_string(),
                category: VulnerabilityCategory::CodeQuality,
                file_path: contract.name.clone(),
                line_number: None,
                code_snippet: None,
                recommendation: Some("Consider alternative patterns to contract destruction.".to_string()),
                references: vec!["https://consensys.github.io/smart-contract-best-practices/recommendations/#be-aware-of-the-tradeoffs-between-send-transfer-and-callvalue".to_string()],
                cwe_id: None,
                tool: "EVM Plugin".to_string(),
                confidence: 0.7,
            });
        }

        // Check for unchecked external calls
        if contract.source_code.contains(".call(") && !contract.source_code.contains("require(") {
            vulnerabilities.push(Vulnerability {
                id: uuid::Uuid::new_v4().to_string(),
                title: "Unchecked External Call".to_string(),
                description: "The contract makes external calls without checking return values.".to_string(),
                severity: "High".to_string(),
                category: VulnerabilityCategory::UnhandledExceptions,
                file_path: contract.name.clone(),
                line_number: None,
                code_snippet: None,
                recommendation: Some("Always check return values of external calls and handle failures appropriately.".to_string()),
                references: vec!["https://consensys.github.io/smart-contract-best-practices/recommendations/#handle-errors-in-external-calls".to_string()],
                cwe_id: Some("CWE-252".to_string()),
                tool: "EVM Plugin".to_string(),
                confidence: 0.8,
            });
        }

        // Check for gas limit issues
        for function in &contract.functions {
            if function.body.contains("while(") || function.body.contains("for(") {
                vulnerabilities.push(Vulnerability {
                    id: uuid::Uuid::new_v4().to_string(),
                    title: format!("Potential Gas Limit Issue in {}", function.name),
                    description: "Function contains loops that might exceed gas limits.".to_string(),
                    severity: "Medium".to_string(),
                    category: VulnerabilityCategory::DenialOfService,
                    file_path: contract.name.clone(),
                    line_number: Some(function.line_number),
                    code_snippet: None,
                    recommendation: Some("Implement gas-efficient alternatives or add proper bounds checking.".to_string()),
                    references: vec!["https://consensys.github.io/smart-contract-best-practices/recommendations/#gas-limit-dos-on-a-contract-via-unbounded-operations".to_string()],
                    cwe_id: Some("CWE-400".to_string()),
                    tool: "EVM Plugin".to_string(),
                    confidence: 0.6,
                });
            }
        }

        Ok(vulnerabilities)
    }
}

impl BlockchainPlugin for EVMPlugin {
    fn name(&self) -> &'static str {
        "EVM"
    }

    fn supported_languages(&self) -> Vec<&'static str> {
        vec!["solidity", "vyper"]
    }

    fn analyze_contract(&self, contract: &ParsedContract) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Run basic checks
        vulnerabilities.extend(self.run_basic_checks(contract)?);

        // Run Slither analysis if available
        if self.is_slither_available() {
            match tokio::runtime::Runtime::new()?.block_on(self.run_slither_analysis(contract)) {
                Ok(slither_vulns) => vulnerabilities.extend(slither_vulns),
                Err(e) => log::warn!("Slither analysis failed: {}", e),
            }
        }

        Ok(vulnerabilities)
    }

    fn validate_contract(&self, contract: &ParsedContract) -> Result<bool> {
        // Basic validation checks
        if contract.source_code.is_empty() {
            return Ok(false);
        }

        // Check for valid Solidity syntax (basic check)
        if !contract.source_code.contains("pragma solidity") && !contract.source_code.contains("contract") {
            return Ok(false);
        }

        // Check for minimum viable contract structure
        if contract.functions.is_empty() && contract.state_variables.is_empty() {
            return Ok(false);
        }

        Ok(true)
    }

    fn get_analysis_tools(&self) -> Vec<&'static str> {
        self.tools.clone()
    }
}

impl Default for EVMPlugin {
    fn default() -> Self {
        Self::new()
    }
}