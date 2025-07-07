//! Core analysis engine for smart contract security auditing
//! 
//! This module orchestrates the security analysis process, coordinating
//! static analysis tools, dynamic analysis, and AI-powered vulnerability detection.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tokio::process::Command;

use crate::core::ai_assist::AIAssistant;
use crate::core::parser::{ContractParser, ParsedContract};
use crate::core::fetcher::ContractFetcher;
use crate::plugins::PluginManager;
use crate::report::vulnerability::{Vulnerability, VulnerabilityCategory};
use crate::utils::config::Config;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResults {
    pub contract_name: String,
    pub vulnerabilities: Vec<Vulnerability>,
    pub analysis_summary: AnalysisSummary,
    pub recommendations: Vec<String>,
    pub metrics: AnalysisMetrics,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisSummary {
    pub total_vulnerabilities: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub analysis_duration: f64,
    pub tools_used: Vec<String>,
    pub coverage_percentage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisMetrics {
    pub lines_of_code: usize,
    pub functions_analyzed: usize,
    pub complexity_score: f64,
    pub security_score: f64,
    pub gas_optimization_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreativeProbe {
    pub title: String,
    pub description: String,
    pub severity: String,
    pub attack_vector: String,
    pub impact: String,
    pub proof_of_concept: Option<String>,
    pub recommended_fix: Option<String>,
    pub confidence: f64,
}

pub struct AnalysisEngine {
    config: Config,
    plugin_manager: PluginManager,
    ai_assistant: AIAssistant,
    contract_parser: ContractParser,
}

impl AnalysisEngine {
    /// Create a new analysis engine
    pub fn new(config: Config, plugin_manager: PluginManager) -> Self {
        let ai_assistant = AIAssistant::new(config.clone());
        let contract_parser = ContractParser::new().expect("Failed to create contract parser");

        Self {
            config,
            plugin_manager,
            ai_assistant,
            contract_parser,
        }
    }

    /// Analyze contracts for vulnerabilities
    pub async fn analyze_contracts(
        &self,
        input_path: &Path,
        target: &str,
        depth: &str,
        use_ai: bool,
    ) -> Result<AnalysisResults> {
        let start_time = std::time::Instant::now();
        
        println!("🔍 Starting security analysis...");
        
        // Fetch contracts
        let fetcher = ContractFetcher::new(self.config.clone());
        let contracts = fetcher.fetch_from_local(input_path.to_str().unwrap()).await?;
        
        if contracts.is_empty() {
            return Err(anyhow!("No contracts found in the specified path"));
        }

        let mut all_vulnerabilities = Vec::new();
        let mut tools_used = Vec::new();
        let mut total_functions = 0;
        let mut total_lines = 0;

        // Analyze each contract
        for contract in &contracts {
            println!("📄 Analyzing contract: {}", contract.name);
            
            // Parse contract
            let parsed_contract = self.contract_parser.parse_contract(contract)?;
            total_functions += parsed_contract.functions.len();
            total_lines += parsed_contract.source_code.lines().count();

            // Run static analysis based on target platform
            let static_vulnerabilities = self.run_static_analysis(&parsed_contract, target, depth).await?;
            all_vulnerabilities.extend(static_vulnerabilities);

            // Run dynamic analysis if requested
            if depth == "deep" {
                let dynamic_vulnerabilities = self.run_dynamic_analysis(&parsed_contract, target).await?;
                all_vulnerabilities.extend(dynamic_vulnerabilities);
            }

            // Run AI-powered analysis if requested
            if use_ai {
                println!("🧠 Running AI-powered analysis...");
                let ai_vulnerabilities = self.ai_assistant.analyze_contract(&parsed_contract).await?;
                all_vulnerabilities.extend(ai_vulnerabilities);
                tools_used.push("AI Assistant".to_string());
            }
        }

        // Calculate metrics
        let analysis_duration = start_time.elapsed().as_secs_f64();
        let security_score = self.calculate_security_score(&all_vulnerabilities);
        let complexity_score = self.calculate_complexity_score(total_functions, total_lines);

        // Generate summary
        let analysis_summary = self.generate_analysis_summary(&all_vulnerabilities, analysis_duration, &tools_used);
        
        // Generate recommendations
        let recommendations = self.generate_recommendations(&all_vulnerabilities);

        Ok(AnalysisResults {
            contract_name: contracts[0].name.clone(),
            vulnerabilities: all_vulnerabilities,
            analysis_summary,
            recommendations,
            metrics: AnalysisMetrics {
                lines_of_code: total_lines,
                functions_analyzed: total_functions,
                complexity_score,
                security_score,
                gas_optimization_score: 0.0, // TODO: Implement gas analysis
            },
            timestamp: chrono::Utc::now(),
        })
    }

    /// Generate creative exploit probes using AI
    pub async fn generate_creative_probes(
        &self,
        input_path: &Path,
        creativity: &str,
        llm_backend: &str,
        generate_poc: bool,
    ) -> Result<Vec<CreativeProbe>> {
        println!("🎯 Generating creative vulnerability probes...");

        // Fetch and parse contracts
        let fetcher = ContractFetcher::new(self.config.clone());
        let contracts = fetcher.fetch_from_local(input_path.to_str().unwrap()).await?;
        
        if contracts.is_empty() {
            return Err(anyhow!("No contracts found in the specified path"));
        }

        let mut all_probes = Vec::new();

        for contract in &contracts {
            let parsed_contract = self.contract_parser.parse_contract(contract)?;
            let probes = self.ai_assistant.generate_creative_probes(
                &parsed_contract,
                creativity,
                llm_backend,
                generate_poc,
            ).await?;
            
            all_probes.extend(probes);
        }

        println!("✨ Generated {} creative probes", all_probes.len());
        Ok(all_probes)
    }

    /// Run static analysis using various tools
    async fn run_static_analysis(
        &self,
        contract: &ParsedContract,
        target: &str,
        depth: &str,
    ) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        match target {
            "evm" => {
                // Run Slither
                if let Ok(slither_results) = self.run_slither(contract).await {
                    vulnerabilities.extend(slither_results);
                }

                // Run Mythril for deep analysis
                if depth == "deep" {
                    if let Ok(mythril_results) = self.run_mythril(contract).await {
                        vulnerabilities.extend(mythril_results);
                    }
                }
            }
            "move" => {
                // Run Move Prover
                if let Ok(move_results) = self.run_move_prover(contract).await {
                    vulnerabilities.extend(move_results);
                }
            }
            "cairo" => {
                // Run Cairo analysis tools
                if let Ok(cairo_results) = self.run_cairo_analysis(contract).await {
                    vulnerabilities.extend(cairo_results);
                }
            }
            _ => {
                return Err(anyhow!("Unsupported target platform: {}", target));
            }
        }

        Ok(vulnerabilities)
    }

    /// Run dynamic analysis (fuzzing, etc.)
    async fn run_dynamic_analysis(
        &self,
        contract: &ParsedContract,
        target: &str,
    ) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        match target {
            "evm" => {
                // Run Echidna fuzzing
                if let Ok(echidna_results) = self.run_echidna(contract).await {
                    vulnerabilities.extend(echidna_results);
                }
            }
            _ => {
                // Other platforms - implement as needed
            }
        }

        Ok(vulnerabilities)
    }

    /// Run Slither static analysis
    async fn run_slither(&self, contract: &ParsedContract) -> Result<Vec<Vulnerability>> {
        println!("  🔍 Running Slither static analysis...");

        // Create temporary file for analysis
        let temp_file = tempfile::NamedTempFile::new()?;
        std::fs::write(temp_file.path(), &contract.source_code)?;

        // Run Slither
        let output = Command::new("slither")
            .arg(temp_file.path())
            .arg("--json")
            .arg("-")
            .output()
            .await?;

        if !output.status.success() {
            log::warn!("Slither execution failed: {}", String::from_utf8_lossy(&output.stderr));
            return Ok(Vec::new());
        }

        // Parse Slither output
        let slither_output = String::from_utf8_lossy(&output.stdout);
        self.parse_slither_output(&slither_output, &contract.name)
    }

    /// Run Mythril symbolic execution
    async fn run_mythril(&self, contract: &ParsedContract) -> Result<Vec<Vulnerability>> {
        println!("  🔮 Running Mythril symbolic execution...");

        // Create temporary file
        let temp_file = tempfile::NamedTempFile::new()?;
        std::fs::write(temp_file.path(), &contract.source_code)?;

        // Run Mythril
        let output = Command::new("myth")
            .arg("analyze")
            .arg(temp_file.path())
            .arg("--output")
            .arg("json")
            .output()
            .await?;

        if !output.status.success() {
            log::warn!("Mythril execution failed: {}", String::from_utf8_lossy(&output.stderr));
            return Ok(Vec::new());
        }

        // Parse Mythril output
        let mythril_output = String::from_utf8_lossy(&output.stdout);
        self.parse_mythril_output(&mythril_output, &contract.name)
    }

    /// Run Echidna fuzzing
    async fn run_echidna(&self, contract: &ParsedContract) -> Result<Vec<Vulnerability>> {
        println!("  🎲 Running Echidna fuzzing...");

        // Create temporary file
        let temp_file = tempfile::NamedTempFile::new()?;
        std::fs::write(temp_file.path(), &contract.source_code)?;

        // Run Echidna
        let output = Command::new("echidna-test")
            .arg(temp_file.path())
            .arg("--format")
            .arg("json")
            .output()
            .await?;

        if !output.status.success() {
            log::warn!("Echidna execution failed: {}", String::from_utf8_lossy(&output.stderr));
            return Ok(Vec::new());
        }

        // Parse Echidna output
        let echidna_output = String::from_utf8_lossy(&output.stdout);
        self.parse_echidna_output(&echidna_output, &contract.name)
    }

    /// Run Move Prover analysis
    async fn run_move_prover(&self, _contract: &ParsedContract) -> Result<Vec<Vulnerability>> {
        println!("  📐 Running Move Prover analysis...");
        
        // TODO: Implement Move Prover integration
        Ok(Vec::new())
    }

    /// Run Cairo analysis
    async fn run_cairo_analysis(&self, _contract: &ParsedContract) -> Result<Vec<Vulnerability>> {
        println!("  🏛️  Running Cairo analysis...");
        
        // TODO: Implement Cairo analysis integration
        Ok(Vec::new())
    }

    /// Parse Slither JSON output
    fn parse_slither_output(&self, output: &str, contract_name: &str) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Try to parse as JSON
        if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(output) {
            if let Some(results) = json_value.get("results") {
                if let Some(detectors) = results.get("detectors") {
                    if let Some(detector_array) = detectors.as_array() {
                        for detector in detector_array {
                            if let Some(vuln) = self.parse_slither_detector(detector, contract_name) {
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
    fn parse_slither_detector(&self, detector: &serde_json::Value, contract_name: &str) -> Option<Vulnerability> {
        let check = detector.get("check")?.as_str()?;
        let impact = detector.get("impact")?.as_str()?;
        let confidence = detector.get("confidence")?.as_str()?;
        let description = detector.get("description")?.as_str()?;

        // Extract line number and file path
        let mut line_number = None;
        let file_path = contract_name.to_string();

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
                }
            }
        }

        Some(Vulnerability {
            id: uuid::Uuid::new_v4().to_string(),
            title: format!("Slither: {}", check),
            description: description.to_string(),
            severity: self.map_slither_severity(impact),
            category: self.map_slither_category(check),
            file_path,
            line_number,
            code_snippet: None,
            recommendation: Some(format!("Review the {} issue detected by Slither", check)),
            references: vec!["https://github.com/crytic/slither".to_string()],
            cwe_id: None,
            tool: "Slither".to_string(),
            confidence: self.map_confidence(confidence),
        })
    }

    /// Parse Mythril JSON output
    fn parse_mythril_output(&self, output: &str, contract_name: &str) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Try to parse as JSON
        if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(output) {
            if let Some(issues) = json_value.get("issues") {
                if let Some(issue_array) = issues.as_array() {
                    for issue in issue_array {
                        if let Some(vuln) = self.parse_mythril_issue(issue, contract_name) {
                            vulnerabilities.push(vuln);
                        }
                    }
                }
            }
        }

        Ok(vulnerabilities)
    }

    /// Parse individual Mythril issue
    fn parse_mythril_issue(&self, issue: &serde_json::Value, contract_name: &str) -> Option<Vulnerability> {
        let title = issue.get("title")?.as_str()?;
        let description = issue.get("description")?.as_str()?;
        let severity = issue.get("severity")?.as_str()?;
        let swc_id = issue.get("swc-id")?.as_str()?;

        // Extract line number
        let mut line_number = None;
        if let Some(source_map) = issue.get("source_map") {
            if let Some(line) = source_map.get("line") {
                line_number = line.as_u64().map(|l| l as usize);
            }
        }

        Some(Vulnerability {
            id: uuid::Uuid::new_v4().to_string(),
            title: format!("Mythril: {}", title),
            description: description.to_string(),
            severity: self.map_mythril_severity(severity),
            category: VulnerabilityCategory::SymbolicExecution,
            file_path: contract_name.to_string(),
            line_number,
            code_snippet: None,
            recommendation: Some("Review the symbolic execution result from Mythril".to_string()),
            references: vec!["https://github.com/ConsenSys/mythril".to_string()],
            cwe_id: Some(swc_id.to_string()),
            tool: "Mythril".to_string(),
            confidence: 0.8,
        })
    }

    /// Parse Echidna output
    fn parse_echidna_output(&self, output: &str, contract_name: &str) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Parse Echidna results (implementation depends on output format)
        // For now, create a placeholder vulnerability if fuzzing found issues
        if output.contains("FAILED") || output.contains("AssertionFailed") {
            vulnerabilities.push(Vulnerability {
                id: uuid::Uuid::new_v4().to_string(),
                title: "Echidna: Fuzzing Assertion Failure".to_string(),
                description: "Echidna fuzzing detected assertion failures or property violations".to_string(),
                severity: "High".to_string(),
                category: VulnerabilityCategory::Fuzzing,
                file_path: contract_name.to_string(),
                line_number: None,
                code_snippet: None,
                recommendation: Some("Review the fuzzing results and fix any assertion failures".to_string()),
                references: vec!["https://github.com/crytic/echidna".to_string()],
                cwe_id: None,
                tool: "Echidna".to_string(),
                confidence: 0.9,
            });
        }

        Ok(vulnerabilities)
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

    /// Map Mythril severity to standard severity
    fn map_mythril_severity(&self, severity: &str) -> String {
        match severity.to_lowercase().as_str() {
            "high" => "High".to_string(),
            "medium" => "Medium".to_string(),
            "low" => "Low".to_string(),
            _ => "Medium".to_string(),
        }
    }

    /// Map Slither check to vulnerability category
    fn map_slither_category(&self, check: &str) -> VulnerabilityCategory {
        match check {
            "reentrancy-eth" | "reentrancy-no-eth" => VulnerabilityCategory::Reentrancy,
            "unchecked-transfer" | "unchecked-send" => VulnerabilityCategory::UnhandledExceptions,
            "tx-origin" => VulnerabilityCategory::AccessControl,
            "timestamp" => VulnerabilityCategory::TimestampDependence,
            "low-level-calls" => VulnerabilityCategory::LowLevelCalls,
            _ => VulnerabilityCategory::Other,
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

    /// Calculate security score based on vulnerabilities
    fn calculate_security_score(&self, vulnerabilities: &[Vulnerability]) -> f64 {
        if vulnerabilities.is_empty() {
            return 100.0;
        }

        let mut score: f64 = 100.0;
        
        for vuln in vulnerabilities {
            let penalty = match vuln.severity.as_str() {
                "Critical" => 25.0,
                "High" => 15.0,
                "Medium" => 8.0,
                "Low" => 3.0,
                _ => 1.0,
            };
            score -= penalty;
        }

        score.max(0.0)
    }

    /// Calculate complexity score
    fn calculate_complexity_score(&self, functions: usize, lines: usize) -> f64 {
        // Simple complexity calculation based on functions and lines
        let function_complexity = functions as f64 * 0.1;
        let line_complexity = lines as f64 * 0.01;
        
        (function_complexity + line_complexity).min(100.0)
    }

    /// Generate analysis summary
    fn generate_analysis_summary(
        &self,
        vulnerabilities: &[Vulnerability],
        duration: f64,
        tools_used: &[String],
    ) -> AnalysisSummary {
        let mut critical_count = 0;
        let mut high_count = 0;
        let mut medium_count = 0;
        let mut low_count = 0;
        let mut info_count = 0;

        for vuln in vulnerabilities {
            match vuln.severity.as_str() {
                "Critical" => critical_count += 1,
                "High" => high_count += 1,
                "Medium" => medium_count += 1,
                "Low" => low_count += 1,
                _ => info_count += 1,
            }
        }

        AnalysisSummary {
            total_vulnerabilities: vulnerabilities.len(),
            critical_count,
            high_count,
            medium_count,
            low_count,
            info_count,
            analysis_duration: duration,
            tools_used: tools_used.to_vec(),
            coverage_percentage: 85.0, // TODO: Calculate actual coverage
        }
    }

    /// Generate security recommendations
    fn generate_recommendations(&self, vulnerabilities: &[Vulnerability]) -> Vec<String> {
        let mut recommendations = Vec::new();

        if vulnerabilities.is_empty() {
            recommendations.push("Great job! No vulnerabilities were found in the initial analysis.".to_string());
            recommendations.push("Consider running a deeper analysis with fuzzing and formal verification.".to_string());
        } else {
            recommendations.push("Address high and critical severity vulnerabilities immediately.".to_string());
            recommendations.push("Implement comprehensive unit tests for all smart contract functions.".to_string());
            recommendations.push("Consider getting a professional security audit before deployment.".to_string());
            recommendations.push("Set up continuous security monitoring for your smart contracts.".to_string());
        }

        recommendations.push("Follow secure coding practices and use established security patterns.".to_string());
        recommendations.push("Keep your dependencies up to date and monitor for new vulnerabilities.".to_string());

        recommendations
    }
}
