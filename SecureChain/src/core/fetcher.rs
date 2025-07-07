//! Contract fetching functionality
//! 
//! This module handles fetching smart contracts from various sources
//! including blockchain explorers, GitHub repositories, and local files.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use crate::utils::config::Config;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractInfo {
    pub name: String,
    pub address: String,
    pub source_code: String,
    pub compiler_version: String,
    pub optimization: bool,
    pub network: String,
    pub verified: bool,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtherscanResponse {
    pub status: String,
    pub message: String,
    pub result: Vec<EtherscanContract>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtherscanContract {
    #[serde(rename = "SourceCode")]
    pub source_code: String,
    #[serde(rename = "ABI")]
    pub abi: String,
    #[serde(rename = "ContractName")]
    pub contract_name: String,
    #[serde(rename = "CompilerVersion")]
    pub compiler_version: String,
    #[serde(rename = "OptimizationUsed")]
    pub optimization_used: String,
    #[serde(rename = "Runs")]
    pub runs: String,
    #[serde(rename = "ConstructorArguments")]
    pub constructor_arguments: String,
    #[serde(rename = "EVMVersion")]
    pub evm_version: String,
    #[serde(rename = "Library")]
    pub library: String,
    #[serde(rename = "LicenseType")]
    pub license_type: String,
    #[serde(rename = "Proxy")]
    pub proxy: String,
    #[serde(rename = "Implementation")]
    pub implementation: String,
    #[serde(rename = "SwarmSource")]
    pub swarm_source: String,
}

pub struct ContractFetcher {
    config: Config,
}

impl ContractFetcher {
    /// Create a new contract fetcher
    pub fn new(config: Config) -> Self {
        Self {
            config,
        }
    }

    /// Fetch contracts from various sources
    pub async fn fetch_contracts(
        &self,
        source: &str,
        address: &str,
        api_key: Option<&str>,
    ) -> Result<Vec<ContractInfo>> {
        match source {
            "etherscan" | "ethereum" | "polygon" | "bsc" => {
                self.fetch_from_etherscan(address, api_key.unwrap_or("")).await
            },
            "github" => self.fetch_from_github(address).await,
            "local" => self.fetch_from_local(address).await,
            _ => Err(anyhow!("Unsupported source: {}", source)),
        }
    }

    /// Fetch contract from Etherscan
    async fn fetch_from_etherscan(&self, address: &str, network: &str) -> Result<Vec<ContractInfo>> {
        let api_key = std::env::var("ETHERSCAN_API_KEY").unwrap_or_else(|_| "YourApiKeyToken".to_string());

        let base_url = match network {
            "ethereum" => "https://api.etherscan.io/api",
            "polygon" => "https://api.polygonscan.com/api",
            "arbitrum" => "https://api.arbiscan.io/api",
            "optimism" => "https://api-optimistic.etherscan.io/api",
            "bsc" => "https://api.bscscan.com/api",
            _ => return Err(anyhow!("Unsupported network: {}", network)),
        };

        let url = format!(
            "{}?module=contract&action=getsourcecode&address={}&apikey={}",
            base_url, address, api_key
        );

        println!("Fetching contract from: {}", url);

        let response = ureq::get(&url)
            .query("module", "contract")
            .query("action", "getsourcecode") 
            .query("address", address)
            .query("apikey", &api_key)
            .call()?;

        let body = response.into_string()?;
        let etherscan_response: EtherscanResponse = serde_json::from_str(&body)?;

        if etherscan_response.status != "1" {
            return Err(anyhow!("Etherscan API error: {}", etherscan_response.message));
        }

        let mut contracts = Vec::new();
        for contract in etherscan_response.result {
            if contract.source_code.is_empty() {
                continue;
            }

            let mut metadata = HashMap::new();
            metadata.insert("abi".to_string(), contract.abi);
            metadata.insert("constructor_arguments".to_string(), contract.constructor_arguments);
            metadata.insert("evm_version".to_string(), contract.evm_version);
            metadata.insert("library".to_string(), contract.library);
            metadata.insert("license_type".to_string(), contract.license_type);
            metadata.insert("proxy".to_string(), contract.proxy);
            metadata.insert("implementation".to_string(), contract.implementation);

            contracts.push(ContractInfo {
                name: contract.contract_name,
                address: address.to_string(),
                source_code: contract.source_code,
                compiler_version: contract.compiler_version,
                optimization: contract.optimization_used == "1",
                network: network.to_string(),
                verified: true,
                metadata,
            });
        }

        Ok(contracts)
    }

    /// Fetch contracts from GitHub
    async fn fetch_from_github(&self, query: &str) -> Result<Vec<ContractInfo>> {
        let github_token = std::env::var("GITHUB_TOKEN").ok();

        let url = format!(
            "https://api.github.com/search/code?q={}&sort=indexed&order=desc",
            urlencoding::encode(query)
        );

        let mut request = ureq::get(&url)
            .set("User-Agent", "BugForgeX/1.0");

        if let Some(token) = &github_token {
            request = request.set("Authorization", &format!("token {}", token));
        }

        let response = request.call()?;

        let data: serde_json::Value = response.into_json()?;

        let mut contracts = Vec::new();

        if let Some(items) = data["items"].as_array() {
            for item in items.iter().take(10) { // Limit to first 10 results
                if let (Some(name), Some(download_url)) = (
                    item["name"].as_str(),
                    item["download_url"].as_str(),
                ) {
                    if name.ends_with(".sol") {
                        match ureq::get(download_url).call() {
                            Ok(content_response) => {
                                if let Ok(source_code) = content_response.into_string() {
                                    contracts.push(ContractInfo {
                                        name: name.to_string(),
                                        address: "".to_string(),
                                        source_code,
                                        compiler_version: "unknown".to_string(),
                                        optimization: false,
                                        network: "github".to_string(),
                                        verified: false,
                                        metadata: HashMap::new(),
                                    });
                                }
                            }
                            Err(e) => {
                                log::warn!("Failed to fetch contract {}: {}", name, e);
                            }
                        }
                    }
                }
            }
        }

        Ok(contracts)
    }

    /// Fetch contracts from local file system
    pub async fn fetch_from_local(&self, path: &str) -> Result<Vec<ContractInfo>> {
        let path = Path::new(path);
        let mut contracts = Vec::new();

        if path.is_file() {
            // Single file
            let source_code = std::fs::read_to_string(path)?;
            let name = path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();

            contracts.push(ContractInfo {
                name,
                address: "".to_string(),
                source_code,
                compiler_version: "unknown".to_string(),
                optimization: false,
                network: "local".to_string(),
                verified: false,
                metadata: HashMap::new(),
            });
        } else if path.is_dir() {
            // Directory - recursively find .sol files
            let walker = walkdir::WalkDir::new(path);
            for entry in walker.into_iter().filter_map(|e| e.ok()) {
                let entry_path = entry.path();
                if entry_path.is_file() {
                    if let Some(extension) = entry_path.extension() {
                        if extension == "sol" {
                            let source_code = std::fs::read_to_string(entry_path)?;
                            let name = entry_path.file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("unknown")
                                .to_string();

                            contracts.push(ContractInfo {
                                name,
                                address: "".to_string(),
                                source_code,
                                compiler_version: "unknown".to_string(),
                                optimization: false,
                                network: "local".to_string(),
                                verified: false,
                                metadata: HashMap::new(),
                            });
                        }
                    }
                }
            }
        } else {
            return Err(anyhow!("Path does not exist: {}", path.display()));
        }

        Ok(contracts)
    }
}