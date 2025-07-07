//! AI-powered vulnerability detection and creative analysis
//! 
//! This module integrates with language models to provide creative
//! vulnerability detection and exploit hypothesis generation.

use anyhow::{anyhow, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::core::analyzer::CreativeProbe;
use crate::core::parser::ParsedContract;
use crate::report::vulnerability::{Vulnerability, VulnerabilityCategory};
use crate::utils::config::Config;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIAnalysisRequest {
    pub contract_code: String,
    pub contract_name: String,
    pub analysis_type: String,
    pub creativity_level: String,
    pub include_poc: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIAnalysisResponse {
    pub vulnerabilities: Vec<AIVulnerability>,
    pub creative_insights: Vec<String>,
    pub recommendations: Vec<String>,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIVulnerability {
    pub title: String,
    pub description: String,
    pub severity: String,
    pub category: String,
    pub line_number: Option<usize>,
    pub code_snippet: Option<String>,
    pub exploit_scenario: Option<String>,
    pub proof_of_concept: Option<String>,
    pub fix_suggestion: Option<String>,
    pub confidence: f64,
}

pub struct AIAssistant {
    client: Client,
    config: Config,
}

impl AIAssistant {
    /// Create a new AI assistant
    pub fn new(config: Config) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .expect("Failed to create HTTP client");

        Self { client, config }
    }

    /// Analyze contract using AI
    pub async fn analyze_contract(&self, contract: &ParsedContract) -> Result<Vec<Vulnerability>> {
        let prompt = self.generate_analysis_prompt(contract)?;

        match self.config.ai.backend.as_str() {
            "openai" => self.analyze_with_openai(&prompt, contract).await,
            "anthropic" => self.analyze_with_anthropic(&prompt, contract).await,
            "local" => self.analyze_with_local_llm(&prompt, contract).await,
            _ => Err(anyhow!("Unsupported AI backend: {}", self.config.ai.backend)),
        }
    }

    /// Generate creative vulnerability probes
    pub async fn generate_creative_probes(
        &self,
        contract: &ParsedContract,
        creativity: &str,
        llm_backend: &str,
        generate_poc: bool,
    ) -> Result<Vec<CreativeProbe>> {
        let prompt = self.generate_creative_prompt(contract, creativity, generate_poc)?;

        match llm_backend {
            "openai" => self.generate_probes_with_openai(&prompt, contract, generate_poc).await,
            "anthropic" => self.generate_probes_with_anthropic(&prompt, contract, generate_poc).await,
            "local" => self.generate_probes_with_local_llm(&prompt, contract, generate_poc).await,
            _ => Err(anyhow!("Unsupported LLM backend: {}", llm_backend)),
        }
    }

    /// Generate analysis prompt for AI
    fn generate_analysis_prompt(&self, contract: &ParsedContract) -> Result<String> {
        let mut prompt = String::new();

        prompt.push_str("You are a senior blockchain security auditor specializing in smart contract vulnerabilities. ");
        prompt.push_str("Analyze the following smart contract for security issues, focusing on:\n\n");
        prompt.push_str("1. Reentrancy vulnerabilities\n");
        prompt.push_str("2. Access control issues\n");
        prompt.push_str("3. Integer overflow/underflow\n");
        prompt.push_str("4. Unchecked external calls\n");
        prompt.push_str("5. Gas optimization issues\n");
        prompt.push_str("6. Logic errors and edge cases\n");
        prompt.push_str("7. Front-running opportunities\n");
        prompt.push_str("8. Timestamp dependence\n");
        prompt.push_str("9. Denial of service vulnerabilities\n");
        prompt.push_str("10. Upgrade mechanism flaws\n\n");

        prompt.push_str(&format!("Contract Name: {}\n", contract.name));
        prompt.push_str(&format!("Compiler Version: {}\n", contract.compiler_version));
        prompt.push_str(&format!("Functions: {}\n", contract.functions.len()));
        prompt.push_str(&format!("State Variables: {}\n", contract.state_variables.len()));

        if !contract.inheritance.is_empty() {
            prompt.push_str(&format!("Inherits from: {}\n", contract.inheritance.join(", ")));
        }

        prompt.push_str("\nContract Source Code:\n");
        prompt.push_str("```solidity\n");
        prompt.push_str(&contract.source_code);
        prompt.push_str("\n```\n\n");

        prompt.push_str("Please provide a detailed analysis in JSON format with the following structure:\n");
        prompt.push_str("{\n");
        prompt.push_str("  \"vulnerabilities\": [\n");
        prompt.push_str("    {\n");
        prompt.push_str("      \"title\": \"Vulnerability Title\",\n");
        prompt.push_str("      \"description\": \"Detailed description\",\n");
        prompt.push_str("      \"severity\": \"Critical|High|Medium|Low|Info\",\n");
        prompt.push_str("      \"category\": \"Category\",\n");
        prompt.push_str("      \"line_number\": number,\n");
        prompt.push_str("      \"code_snippet\": \"relevant code\",\n");
        prompt.push_str("      \"exploit_scenario\": \"how to exploit\",\n");
        prompt.push_str("      \"fix_suggestion\": \"how to fix\",\n");
        prompt.push_str("      \"confidence\": 0.0-1.0\n");
        prompt.push_str("    }\n");
        prompt.push_str("  ],\n");
        prompt.push_str("  \"creative_insights\": [\"insight1\", \"insight2\"],\n");
        prompt.push_str("  \"recommendations\": [\"rec1\", \"rec2\"]\n");
        prompt.push_str("}\n");

        Ok(prompt)
    }

    /// Generate creative prompt for vulnerability discovery
    fn generate_creative_prompt(&self, contract: &ParsedContract, creativity: &str, generate_poc: bool) -> Result<String> {
        let mut prompt = String::new();

        prompt.push_str("You are a creative blockchain security researcher and white-hat hacker. ");
        prompt.push_str("Your task is to think outside the box and discover novel attack vectors ");
        prompt.push_str("and edge cases that traditional static analysis tools might miss.\n\n");

        match creativity {
            "low" => {
                prompt.push_str("Focus on well-known vulnerability patterns and common mistakes.\n");
            }
            "medium" => {
                prompt.push_str("Explore creative combinations of known vulnerabilities and unusual edge cases.\n");
            }
            "high" => {
                prompt.push_str("Think creatively about novel attack vectors, complex multi-step exploits, ");
                prompt.push_str("and unconventional ways to break the contract's assumptions.\n");
            }
            _ => {
                prompt.push_str("Explore creative vulnerability scenarios.\n");
            }
        }

        prompt.push_str("\nConsider these creative attack scenarios:\n");
        prompt.push_str("1. Economic attacks (flash loans, arbitrage, market manipulation)\n");
        prompt.push_str("2. Governance attacks (vote manipulation, proposal griefing)\n");
        prompt.push_str("3. Cross-protocol interactions and composability risks\n");
        prompt.push_str("4. MEV (Maximal Extractable Value) opportunities\n");
        prompt.push_str("5. Social engineering combined with technical exploits\n");
        prompt.push_str("6. Time-based attacks and deadline manipulation\n");
        prompt.push_str("7. Gas griefing and DoS through resource exhaustion\n");
        prompt.push_str("8. Oracle manipulation and price feed attacks\n");
        prompt.push_str("9. Multi-block attacks and state manipulation\n");
        prompt.push_str("10. Upgrade mechanism exploitation\n\n");

        prompt.push_str(&format!("Contract to analyze: {}\n", contract.name));
        prompt.push_str("```solidity\n");
        prompt.push_str(&contract.source_code);
        prompt.push_str("\n```\n\n");

        if generate_poc {
            prompt.push_str("For each vulnerability, provide a proof-of-concept exploit code.\n");
        }

        prompt.push_str("Provide your analysis in JSON format with creative probes:\n");
        prompt.push_str("{\n");
        prompt.push_str("  \"probes\": [\n");
        prompt.push_str("    {\n");
        prompt.push_str("      \"title\": \"Creative Attack Title\",\n");
        prompt.push_str("      \"description\": \"Detailed attack description\",\n");
        prompt.push_str("      \"severity\": \"Critical|High|Medium|Low\",\n");
        prompt.push_str("      \"attack_vector\": \"How the attack works\",\n");
        prompt.push_str("      \"impact\": \"What damage it can cause\",\n");
        if generate_poc {
            prompt.push_str("      \"proof_of_concept\": \"Exploit code\",\n");
        }
        prompt.push_str("      \"recommended_fix\": \"How to prevent it\",\n");
        prompt.push_str("      \"confidence\": 0.0-1.0\n");
        prompt.push_str("    }\n");
        prompt.push_str("  ]\n");
        prompt.push_str("}\n");

        Ok(prompt)
    }

    /// Analyze with OpenAI GPT
    async fn analyze_with_openai(&self, prompt: &str, contract: &ParsedContract) -> Result<Vec<Vulnerability>> {
        let api_key = std::env::var("OPENAI_API_KEY")
            .map_err(|_| anyhow!("OPENAI_API_KEY environment variable not set"))?;

        let request_body = serde_json::json!({
            "model": "gpt-4",
            "messages": [
                {
                    "role": "system",
                    "content": "You are a senior blockchain security auditor."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "max_tokens": 4000,
            "temperature": 0.1
        });

        let response = self.client
            .post("https://api.openai.com/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await?;

        let response_json: serde_json::Value = response.json().await?;

        if let Some(content) = response_json["choices"][0]["message"]["content"].as_str() {
            self.parse_ai_analysis_response(content, contract)
        } else {
            Err(anyhow!("Invalid response from OpenAI"))
        }
    }

    /// Analyze with Anthropic Claude
    async fn analyze_with_anthropic(&self, prompt: &str, contract: &ParsedContract) -> Result<Vec<Vulnerability>> {
        let api_key = std::env::var("ANTHROPIC_API_KEY")
            .map_err(|_| anyhow!("ANTHROPIC_API_KEY environment variable not set"))?;

        let request_body = serde_json::json!({
            "model": "claude-3-sonnet-20240229",
            "max_tokens": 4000,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        });

        let response = self.client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", api_key)
            .header("Content-Type", "application/json")
            .header("anthropic-version", "2023-06-01")
            .json(&request_body)
            .send()
            .await?;

        let response_json: serde_json::Value = response.json().await?;

        if let Some(content) = response_json["content"][0]["text"].as_str() {
            self.parse_ai_analysis_response(content, contract)
        } else {
            Err(anyhow!("Invalid response from Anthropic"))
        }
    }

    /// Analyze with local LLM (Ollama)
    async fn analyze_with_local_llm(&self, prompt: &str, contract: &ParsedContract) -> Result<Vec<Vulnerability>> {
        let ollama_url = std::env::var("OLLAMA_URL")
            .unwrap_or_else(|_| "http://localhost:11434".to_string());

        let request_body = serde_json::json!({
            "model": "codellama:7b",
            "prompt": prompt,
            "stream": false
        });

        let response = self.client
            .post(&format!("{}/api/generate", ollama_url))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await?;

        let response_json: serde_json::Value = response.json().await?;

        if let Some(content) = response_json["response"].as_str() {
            self.parse_ai_analysis_response(content, contract)
        } else {
            Err(anyhow!("Invalid response from local LLM"))
        }
    }

    /// Generate probes with OpenAI
    async fn generate_probes_with_openai(
        &self,
        prompt: &str,
        _contract: &ParsedContract,
        _generate_poc: bool,
    ) -> Result<Vec<CreativeProbe>> {
        let api_key = std::env::var("OPENAI_API_KEY")
            .map_err(|_| anyhow!("OPENAI_API_KEY environment variable not set"))?;

        let request_body = serde_json::json!({
            "model": "gpt-4",
            "messages": [
                {
                    "role": "system",
                    "content": "You are a creative blockchain security researcher."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "max_tokens": 4000,
            "temperature": 0.3
        });

        let response = self.client
            .post("https://api.openai.com/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await?;

        let response_json: serde_json::Value = response.json().await?;

        if let Some(content) = response_json["choices"][0]["message"]["content"].as_str() {
            self.parse_creative_probe_response(content)
        } else {
            Err(anyhow!("Invalid response from OpenAI"))
        }
    }

    /// Generate probes with Anthropic
    async fn generate_probes_with_anthropic(
        &self,
        prompt: &str,
        _contract: &ParsedContract,
        _generate_poc: bool,
    ) -> Result<Vec<CreativeProbe>> {
        let api_key = std::env::var("ANTHROPIC_API_KEY")
            .map_err(|_| anyhow!("ANTHROPIC_API_KEY environment variable not set"))?;

        let request_body = serde_json::json!({
            "model": "claude-3-sonnet-20240229",
            "max_tokens": 4000,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        });

        let response = self.client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", api_key)
            .header("Content-Type", "application/json")
            .header("anthropic-version", "2023-06-01")
            .json(&request_body)
            .send()
            .await?;

        let response_json: serde_json::Value = response.json().await?;

        if let Some(content) = response_json["content"][0]["text"].as_str() {
            self.parse_creative_probe_response(content)
        } else {
            Err(anyhow!("Invalid response from Anthropic"))
        }
    }

    /// Generate probes with local LLM
    async fn generate_probes_with_local_llm(
        &self,
        prompt: &str,
        _contract: &ParsedContract,
        _generate_poc: bool,
    ) -> Result<Vec<CreativeProbe>> {
        let ollama_url = std::env::var("OLLAMA_URL")
            .unwrap_or_else(|_| "http://localhost:11434".to_string());

        let request_body = serde_json::json!({
            "model": "codellama:7b",
            "prompt": prompt,
            "stream": false
        });

        let response = self.client
            .post(&format!("{}/api/generate", ollama_url))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await?;

        let response_json: serde_json::Value = response.json().await?;

        if let Some(content) = response_json["response"].as_str() {
            self.parse_creative_probe_response(content)
        } else {
            Err(anyhow!("Invalid response from local LLM"))
        }
    }

    /// Parse AI analysis response
    fn parse_ai_analysis_response(&self, content: &str, contract: &ParsedContract) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Try to extract JSON from the response
        if let Some(json_start) = content.find('{') {
            let json_content = &content[json_start..];
            if let Some(json_end) = json_content.rfind('}') {
                let json_str = &json_content[..=json_end];

                if let Ok(analysis_response) = serde_json::from_str::<AIAnalysisResponse>(json_str) {
                    for ai_vuln in analysis_response.vulnerabilities {
                        vulnerabilities.push(Vulnerability {
                            id: uuid::Uuid::new_v4().to_string(),
                            title: format!("AI: {}", ai_vuln.title),
                            description: ai_vuln.description,
                            severity: ai_vuln.severity,
                            category: self.map_ai_category(&ai_vuln.category),
                            file_path: contract.name.clone(),
                            line_number: ai_vuln.line_number,
                            code_snippet: ai_vuln.code_snippet,
                            recommendation: ai_vuln.fix_suggestion,
                            references: vec!["AI Analysis".to_string()],
                            cwe_id: None,
                            tool: "AI Assistant".to_string(),
                            confidence: ai_vuln.confidence,
                        });
                    }
                }
            }
        }

        Ok(vulnerabilities)
    }

    /// Parse creative probe response
    fn parse_creative_probe_response(&self, content: &str) -> Result<Vec<CreativeProbe>> {
        let mut probes = Vec::new();

        // Try to extract JSON from the response
        if let Some(json_start) = content.find('{') {
            let json_content = &content[json_start..];
            if let Some(json_end) = json_content.rfind('}') {
                let json_str = &json_content[..=json_end];

                if let Ok(probe_response) = serde_json::from_str::<serde_json::Value>(json_str) {
                    if let Some(probe_array) = probe_response["probes"].as_array() {
                        for probe_obj in probe_array {
                            if let Some(probe) = self.parse_probe_object(probe_obj) {
                                probes.push(probe);
                            }
                        }
                    }
                }
            }
        }

        Ok(probes)
    }

    /// Parse individual probe object
    fn parse_probe_object(&self, probe_obj: &serde_json::Value) -> Option<CreativeProbe> {
        let title = probe_obj["title"].as_str()?.to_string();
        let description = probe_obj["description"].as_str()?.to_string();
        let severity = probe_obj["severity"].as_str()?.to_string();
        let attack_vector = probe_obj["attack_vector"].as_str()?.to_string();
        let impact = probe_obj["impact"].as_str()?.to_string();
        let proof_of_concept = probe_obj["proof_of_concept"].as_str().map(|s| s.to_string());
        let recommended_fix = probe_obj["recommended_fix"].as_str().map(|s| s.to_string());
        let confidence = probe_obj["confidence"].as_f64().unwrap_or(0.5);

        Some(CreativeProbe {
            title,
            description,
            severity,
            attack_vector,
            impact,
            proof_of_concept,
            recommended_fix,
            confidence,
        })
    }

    /// Map AI category to vulnerability category
    fn map_ai_category(&self, category: &str) -> VulnerabilityCategory {
        match category.to_lowercase().as_str() {
            "reentrancy" => VulnerabilityCategory::Reentrancy,
            "access control" => VulnerabilityCategory::AccessControl,
            "integer overflow" => VulnerabilityCategory::IntegerOverflow,
            "unchecked calls" => VulnerabilityCategory::UnhandledExceptions,
            "timestamp" => VulnerabilityCategory::TimestampDependence,
            "dos" => VulnerabilityCategory::DenialOfService,
            _ => VulnerabilityCategory::Other,
        }
    }
}