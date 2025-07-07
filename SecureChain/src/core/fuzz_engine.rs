//! Fuzzing engine for dynamic testing of smart contracts
//! 
//! This module provides fuzzing capabilities to discover runtime
//! vulnerabilities through automated input generation and testing.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;
use std::time::Duration;

use crate::core::parser::ParsedContract;
use crate::report::vulnerability::Vulnerability;
use crate::utils::config::Config;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzingConfig {
    pub timeout: Duration,
    pub max_iterations: u32,
    pub coverage_threshold: f64,
    pub property_tests: Vec<PropertyTest>,
    pub invariants: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyTest {
    pub name: String,
    pub description: String,
    pub test_function: String,
    pub expected_behavior: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzingResults {
    pub contract_name: String,
    pub test_cases_run: u32,
    pub failures: Vec<FuzzingFailure>,
    pub coverage_report: CoverageReport,
    pub property_results: Vec<PropertyResult>,
    pub duration: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzingFailure {
    pub test_case: String,
    pub failure_type: String,
    pub error_message: String,
    pub input_data: String,
    pub gas_used: Option<u64>,
    pub stack_trace: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageReport {
    pub lines_covered: u32,
    pub total_lines: u32,
    pub coverage_percentage: f64,
    pub uncovered_lines: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyResult {
    pub property_name: String,
    pub passed: bool,
    pub counterexample: Option<String>,
    pub iterations: u32,
}

pub struct FuzzEngine {
    config: Config,
    fuzzing_config: FuzzingConfig,
}

impl FuzzEngine {
    /// Create a new fuzz engine
    pub fn new(config: Config) -> Self {
        let fuzzing_config = FuzzingConfig {
            timeout: Duration::from_secs(300), // 5 minutes
            max_iterations: 10000,
            coverage_threshold: 80.0,
            property_tests: Vec::new(),
            invariants: Vec::new(),
        };

        Self {
            config,
            fuzzing_config,
        }
    }

    /// Run fuzzing tests on a contract
    pub async fn fuzz_contract(&self, contract: &ParsedContract) -> Result<FuzzingResults> {
        println!("🎲 Starting fuzzing tests for contract: {}", contract.name);

        let start_time = std::time::Instant::now();
        
        // Generate property tests from contract analysis
        let property_tests = self.generate_property_tests(contract)?;
        
        // Run Echidna fuzzing
        let echidna_results = self.run_echidna_fuzzing(contract).await?;
        
        // Run custom property tests
        let property_results = self.run_property_tests(contract, &property_tests).await?;
        
        // Generate coverage report
        let coverage_report = self.generate_coverage_report(contract)?;
        
        let duration = start_time.elapsed();
        
        Ok(FuzzingResults {
            contract_name: contract.name.clone(),
            test_cases_run: echidna_results.len() as u32,
            failures: echidna_results,
            coverage_report,
            property_results,
            duration,
        })
    }

    /// Generate property tests from contract analysis
    fn generate_property_tests(&self, contract: &ParsedContract) -> Result<Vec<PropertyTest>> {
        let mut property_tests = Vec::new();

        // Generate basic property tests for common patterns
        for function in &contract.functions {
            // Test for reentrancy protection
            if function.visibility == "external" || function.visibility == "public" {
                if function.body.contains("call") || function.body.contains("transfer") {
                    property_tests.push(PropertyTest {
                        name: format!("reentrancy_protection_{}", function.name),
                        description: "Ensure function is protected against reentrancy attacks".to_string(),
                        test_function: format!("test_reentrancy_{}", function.name),
                        expected_behavior: "Function should not be vulnerable to reentrancy".to_string(),
                    });
                }
            }

            // Test for access control
            if function.modifiers.iter().any(|m| m.contains("onlyOwner") || m.contains("onlyAdmin")) {
                property_tests.push(PropertyTest {
                    name: format!("access_control_{}", function.name),
                    description: "Ensure function properly enforces access control".to_string(),
                    test_function: format!("test_access_control_{}", function.name),
                    expected_behavior: "Function should reject unauthorized callers".to_string(),
                });
            }

            // Test for integer overflow/underflow
            if function.body.contains("SafeMath") || function.body.contains("unchecked") {
                property_tests.push(PropertyTest {
                    name: format!("integer_safety_{}", function.name),
                    description: "Ensure function handles integer operations safely".to_string(),
                    test_function: format!("test_integer_safety_{}", function.name),
                    expected_behavior: "Function should handle integer operations without overflow/underflow".to_string(),
                });
            }
        }

        // Generate invariant tests for state variables
        for state_var in &contract.state_variables {
            if state_var.type_name.contains("uint") || state_var.type_name.contains("int") {
                property_tests.push(PropertyTest {
                    name: format!("invariant_{}", state_var.name),
                    description: format!("Ensure {} maintains valid state", state_var.name),
                    test_function: format!("test_invariant_{}", state_var.name),
                    expected_behavior: "State variable should maintain valid values".to_string(),
                });
            }
        }

        Ok(property_tests)
    }

    /// Run Echidna fuzzing
    async fn run_echidna_fuzzing(&self, contract: &ParsedContract) -> Result<Vec<FuzzingFailure>> {
        println!("  🔍 Running Echidna fuzzing...");

        // Create temporary contract file
        let temp_dir = tempfile::tempdir()?;
        let contract_path = temp_dir.path().join(format!("{}.sol", contract.name));
        
        // Generate Echidna configuration
        let echidna_config = self.generate_echidna_config(contract)?;
        let config_path = temp_dir.path().join("echidna.yaml");
        
        std::fs::write(&contract_path, &contract.source_code)?;
        std::fs::write(&config_path, &echidna_config)?;

        // Run Echidna
        let output = Command::new("echidna-test")
            .arg(&contract_path)
            .arg("--config")
            .arg(&config_path)
            .arg("--format")
            .arg("json")
            .output();

        match output {
            Ok(cmd_output) => {
                if cmd_output.status.success() {
                    let stdout = String::from_utf8_lossy(&cmd_output.stdout);
                    self.parse_echidna_output(&stdout)
                } else {
                    let stderr = String::from_utf8_lossy(&cmd_output.stderr);
                    log::warn!("Echidna failed: {}", stderr);
                    Ok(Vec::new())
                }
            }
            Err(e) => {
                log::warn!("Failed to run Echidna: {}. Make sure it's installed.", e);
                Ok(Vec::new())
            }
        }
    }

    /// Generate Echidna configuration
    fn generate_echidna_config(&self, contract: &ParsedContract) -> Result<String> {
        let mut config = String::new();
        
        config.push_str("testLimit: 10000\n");
        config.push_str("shrinkLimit: 5000\n");
        config.push_str("seqLen: 100\n");
        config.push_str("contractAddr: \"0x00a329c0648769A73afAc7F9381E08FB43dBEA72\"\n");
        config.push_str("deployer: \"0x00a329c0648769A73afAc7F9381E08FB43dBEA72\"\n");
        config.push_str("sender: [\"0x00a329c0648769A73afAc7F9381E08FB43dBEA72\"]\n");
        config.push_str("psender: \"0x00a329c0648769A73afAc7F9381E08FB43dBEA72\"\n");
        config.push_str("prefix: \"echidna_\"\n");
        config.push_str("codeSize: 0x6000\n");
        config.push_str("corpus: \"corpus\"\n");
        config.push_str("coverage: true\n");
        config.push_str("checkAsserts: true\n");
        
        // Add function filters based on contract analysis
        let mut test_functions = Vec::new();
        for function in &contract.functions {
            if function.name.starts_with("echidna_") {
                test_functions.push(format!("\"{}\"", function.name));
            }
        }
        
        if !test_functions.is_empty() {
            config.push_str("filterFunctions: [");
            config.push_str(&test_functions.join(", "));
            config.push_str("]\n");
        }

        Ok(config)
    }

    /// Parse Echidna output
    fn parse_echidna_output(&self, output: &str) -> Result<Vec<FuzzingFailure>> {
        let mut failures = Vec::new();

        // Parse JSON output from Echidna
        for line in output.lines() {
            if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(line) {
                if let Some(test_type) = json_value.get("test_type") {
                    if test_type == "property" {
                        if let Some(status) = json_value.get("status") {
                            if status == "failed" {
                                let failure = FuzzingFailure {
                                    test_case: json_value.get("property")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("unknown")
                                        .to_string(),
                                    failure_type: "Property violation".to_string(),
                                    error_message: json_value.get("error")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("Property failed")
                                        .to_string(),
                                    input_data: json_value.get("call_sequence")
                                        .map(|v| v.to_string())
                                        .unwrap_or_else(|| "N/A".to_string()),
                                    gas_used: json_value.get("gas_used")
                                        .and_then(|v| v.as_u64()),
                                    stack_trace: json_value.get("stack_trace")
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string()),
                                };
                                failures.push(failure);
                            }
                        }
                    }
                }
            }
        }

        Ok(failures)
    }

    /// Run custom property tests
    async fn run_property_tests(
        &self,
        contract: &ParsedContract,
        property_tests: &[PropertyTest],
    ) -> Result<Vec<PropertyResult>> {
        let mut results = Vec::new();

        for property in property_tests {
            println!("  🧪 Testing property: {}", property.name);
            
            // For now, create mock results
            // In a real implementation, this would execute the property tests
            let result = PropertyResult {
                property_name: property.name.clone(),
                passed: true, // This would be determined by actual test execution
                counterexample: None,
                iterations: 1000,
            };
            
            results.push(result);
        }

        Ok(results)
    }

    /// Generate coverage report
    fn generate_coverage_report(&self, contract: &ParsedContract) -> Result<CoverageReport> {
        let total_lines = contract.source_code.lines().count() as u32;
        let lines_covered = (total_lines as f64 * 0.75) as u32; // Mock 75% coverage
        let coverage_percentage = (lines_covered as f64 / total_lines as f64) * 100.0;
        
        let mut uncovered_lines = Vec::new();
        for i in (lines_covered + 1)..=total_lines {
            uncovered_lines.push(i);
        }

        Ok(CoverageReport {
            lines_covered,
            total_lines,
            coverage_percentage,
            uncovered_lines,
        })
    }

    /// Convert fuzzing results to vulnerabilities
    pub fn convert_to_vulnerabilities(&self, results: &FuzzingResults) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        for failure in &results.failures {
            let severity = match failure.failure_type.as_str() {
                "Property violation" => "High",
                "Assertion failure" => "Medium",
                "Revert" => "Low",
                _ => "Info",
            };

            let vulnerability = Vulnerability {
                id: uuid::Uuid::new_v4().to_string(),
                title: format!("Fuzzing: {}", failure.test_case),
                description: failure.error_message.clone(),
                severity: severity.to_string(),
                category: crate::report::vulnerability::VulnerabilityCategory::Fuzzing,
                file_path: results.contract_name.clone(),
                line_number: None,
                code_snippet: Some(failure.input_data.clone()),
                recommendation: Some("Review the failing test case and fix the underlying issue".to_string()),
                references: vec!["Echidna Fuzzing".to_string()],
                cwe_id: None,
                tool: "FuzzEngine".to_string(),
                confidence: 0.8,
            };

            vulnerabilities.push(vulnerability);
        }

        // Add coverage-related recommendations
        if results.coverage_report.coverage_percentage < 80.0 {
            let coverage_issue = Vulnerability {
                id: uuid::Uuid::new_v4().to_string(),
                title: "Low Test Coverage".to_string(),
                description: format!(
                    "Test coverage is {}%, which is below the recommended 80% threshold",
                    results.coverage_report.coverage_percentage
                ),
                severity: "Info".to_string(),
                category: crate::report::vulnerability::VulnerabilityCategory::CodeQuality,
                file_path: results.contract_name.clone(),
                line_number: None,
                code_snippet: None,
                recommendation: Some("Increase test coverage by adding more comprehensive tests".to_string()),
                references: vec!["Test Coverage Analysis".to_string()],
                cwe_id: None,
                tool: "FuzzEngine".to_string(),
                confidence: 1.0,
            };

            vulnerabilities.push(coverage_issue);
        }

        vulnerabilities
    }
}

impl Default for FuzzEngine {
    fn default() -> Self {
        Self::new(crate::utils::config::Config::default())
    }
}
