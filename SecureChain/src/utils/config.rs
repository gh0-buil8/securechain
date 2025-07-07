//! Configuration management for BugForgeX
//! 
//! This module handles loading and managing configuration settings
//! from various sources including files, environment variables, and CLI arguments.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::utils::error::{BugForgeXError, Result};

/// Main configuration structure for BugForgeX
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// General application settings
    pub general: GeneralConfig,
    
    /// AI assistant configuration
    pub ai: AiConfig,
    
    /// Network and API configurations
    pub networks: NetworkConfig,
    
    /// Tool-specific configurations
    pub tools: ToolsConfig,
    
    /// Analysis settings
    pub analysis: AnalysisConfig,
    
    /// Report generation settings
    pub reporting: ReportingConfig,
}

/// General application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    /// Application log level
    pub log_level: String,
    
    /// Maximum concurrent analysis tasks
    pub max_concurrent_tasks: usize,
    
    /// Default output directory
    pub output_dir: PathBuf,
    
    /// Cache directory for downloaded contracts
    pub cache_dir: PathBuf,
    
    /// Enable colored output
    pub colored_output: bool,
    
    /// Default timeout for operations (in seconds)
    pub default_timeout: u64,
}

/// AI assistant configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfig {
    /// AI backend to use (openai, anthropic, local)
    pub backend: String,
    
    /// OpenAI configuration
    pub openai: OpenAiConfig,
    
    /// Anthropic configuration
    pub anthropic: AnthropicConfig,
    
    /// Local LLM configuration
    pub local: LocalLlmConfig,
    
    /// Enable AI-powered analysis by default
    pub enabled_by_default: bool,
    
    /// Maximum tokens for AI requests
    pub max_tokens: u32,
    
    /// Temperature for creative analysis
    pub temperature: f64,
}

/// OpenAI API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAiConfig {
    /// API endpoint URL
    pub api_url: String,
    
    /// Model to use for analysis
    pub model: String,
    
    /// Organization ID (optional)
    pub organization: Option<String>,
    
    /// Rate limit (requests per minute)
    pub rate_limit: u32,
}

/// Anthropic API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnthropicConfig {
    /// API endpoint URL
    pub api_url: String,
    
    /// Model to use for analysis
    pub model: String,
    
    /// Rate limit (requests per minute)
    pub rate_limit: u32,
}

/// Local LLM configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalLlmConfig {
    /// Ollama URL
    pub ollama_url: String,
    
    /// Default model for analysis
    pub default_model: String,
    
    /// Available models
    pub available_models: Vec<String>,
    
    /// GPU acceleration enabled
    pub gpu_acceleration: bool,
}

/// Network and blockchain API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Ethereum network settings
    pub ethereum: BlockchainNetworkConfig,
    
    /// Polygon network settings
    pub polygon: BlockchainNetworkConfig,
    
    /// Arbitrum network settings
    pub arbitrum: BlockchainNetworkConfig,
    
    /// Optimism network settings
    pub optimism: BlockchainNetworkConfig,
    
    /// BSC network settings
    pub bsc: BlockchainNetworkConfig,
    
    /// Solana network settings
    pub solana: SolanaNetworkConfig,
    
    /// GitHub API configuration
    pub github: GitHubConfig,
}

/// Blockchain network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainNetworkConfig {
    /// Explorer API URL
    pub explorer_url: String,
    
    /// RPC endpoint URL
    pub rpc_url: String,
    
    /// Rate limit (requests per second)
    pub rate_limit: u32,
    
    /// Request timeout (seconds)
    pub timeout: u64,
}

/// Solana-specific network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolanaNetworkConfig {
    /// RPC endpoint URL
    pub rpc_url: String,
    
    /// Explorer URL
    pub explorer_url: String,
    
    /// Rate limit (requests per second)
    pub rate_limit: u32,
    
    /// Request timeout (seconds)
    pub timeout: u64,
}

/// GitHub API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubConfig {
    /// GitHub API URL
    pub api_url: String,
    
    /// Rate limit (requests per hour)
    pub rate_limit: u32,
    
    /// Request timeout (seconds)
    pub timeout: u64,
}

/// Analysis tool configurations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolsConfig {
    /// Slither configuration
    pub slither: SlitherConfig,
    
    /// Mythril configuration
    pub mythril: MythrilConfig,
    
    /// Echidna configuration
    pub echidna: EchidnaConfig,
    
    /// Custom tool configurations
    pub custom: HashMap<String, CustomToolConfig>,
}

/// Slither static analyzer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlitherConfig {
    /// Slither executable path
    pub executable: String,
    
    /// Additional command line arguments
    pub args: Vec<String>,
    
    /// Detectors to exclude
    pub exclude_detectors: Vec<String>,
    
    /// Detectors to include only
    pub include_detectors: Vec<String>,
    
    /// Timeout for analysis (seconds)
    pub timeout: u64,
}

/// Mythril symbolic execution configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MythrilConfig {
    /// Mythril executable path
    pub executable: String,
    
    /// Additional command line arguments
    pub args: Vec<String>,
    
    /// Analysis timeout (seconds)
    pub timeout: u64,
    
    /// Maximum number of transactions to analyze
    pub max_depth: u32,
    
    /// Solver timeout (seconds)
    pub solver_timeout: u64,
}

/// Echidna fuzzer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EchidnaConfig {
    /// Echidna executable path
    pub executable: String,
    
    /// Test limit
    pub test_limit: u32,
    
    /// Sequence length
    pub seq_len: u32,
    
    /// Shrink limit
    pub shrink_limit: u32,
    
    /// Timeout for fuzzing (seconds)
    pub timeout: u64,
}

/// Custom tool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomToolConfig {
    /// Tool executable path
    pub executable: String,
    
    /// Command line arguments template
    pub args_template: String,
    
    /// Output format (json, text, xml)
    pub output_format: String,
    
    /// Timeout (seconds)
    pub timeout: u64,
}

/// Analysis configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    /// Default analysis depth
    pub default_depth: String,
    
    /// Enable parallel analysis
    pub parallel_analysis: bool,
    
    /// Maximum analysis threads
    pub max_threads: usize,
    
    /// Cache analysis results
    pub cache_results: bool,
    
    /// Cache TTL (seconds)
    pub cache_ttl: u64,
    
    /// Minimum confidence threshold for reporting
    pub min_confidence: f64,
    
    /// Vulnerability severity filters
    pub severity_filters: Vec<String>,
}

/// Report generation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportingConfig {
    /// Default output format
    pub default_format: String,
    
    /// Include executive summary by default
    pub include_summary: bool,
    
    /// Template directory
    pub template_dir: PathBuf,
    
    /// Custom report templates
    pub custom_templates: HashMap<String, String>,
    
    /// Maximum report size (MB)
    pub max_report_size: u64,
}

impl Config {
    /// Load configuration from default locations
    pub fn load() -> Result<Self> {
        let mut config = Self::default();
        
        // Load from default config file
        if let Ok(default_config) = Self::load_from_file("config/default.toml") {
            config = config.merge(default_config)?;
        }
        
        // Load from user config file
        if let Some(home_dir) = dirs::home_dir() {
            let user_config_path = home_dir.join(".config/bugforgex/config.toml");
            if user_config_path.exists() {
                if let Ok(user_config) = Self::load_from_file(&user_config_path) {
                    config = config.merge(user_config)?;
                }
            }
        }
        
        // Load from environment variables
        config = config.load_from_env()?;
        
        // Validate configuration
        config.validate()?;
        
        Ok(config)
    }
    
    /// Load configuration from a specific file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| BugForgeXError::config(format!("Failed to read config file: {}", e)))?;
        
        let config: Config = toml::from_str(&content)
            .map_err(|e| BugForgeXError::config(format!("Failed to parse config file: {}", e)))?;
        
        Ok(config)
    }
    
    /// Save configuration to file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| BugForgeXError::config(format!("Failed to serialize config: {}", e)))?;
        
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| BugForgeXError::config(format!("Failed to create config directory: {}", e)))?;
        }
        
        std::fs::write(path.as_ref(), content)
            .map_err(|e| BugForgeXError::config(format!("Failed to write config file: {}", e)))?;
        
        Ok(())
    }
    
    /// Load configuration overrides from environment variables
    fn load_from_env(mut self) -> Result<Self> {
        // API Keys
        if let Ok(_openai_key) = std::env::var("OPENAI_API_KEY") {
            log::debug!("Loaded OpenAI API key from environment");
        }
        
        if let Ok(_anthropic_key) = std::env::var("ANTHROPIC_API_KEY") {
            log::debug!("Loaded Anthropic API key from environment");
        }
        
        if let Ok(_etherscan_key) = std::env::var("ETHERSCAN_API_KEY") {
            log::debug!("Loaded Etherscan API key from environment");
        }
        
        if let Ok(_github_token) = std::env::var("GITHUB_TOKEN") {
            log::debug!("Loaded GitHub token from environment");
        }
        
        // Configuration overrides
        if let Ok(log_level) = std::env::var("BUGFORGEX_LOG_LEVEL") {
            self.general.log_level = log_level;
        }
        
        if let Ok(ai_backend) = std::env::var("BUGFORGEX_AI_BACKEND") {
            self.ai.backend = ai_backend;
        }
        
        if let Ok(ollama_url) = std::env::var("OLLAMA_URL") {
            self.ai.local.ollama_url = ollama_url;
        }
        
        if let Ok(output_dir) = std::env::var("BUGFORGEX_OUTPUT_DIR") {
            self.general.output_dir = PathBuf::from(output_dir);
        }
        
        Ok(self)
    }
    
    /// Merge two configurations, with other taking precedence
    fn merge(mut self, other: Config) -> Result<Self> {
        // Merge general settings
        if other.general.log_level != self.general.log_level && other.general.log_level != "info" {
            self.general.log_level = other.general.log_level;
        }
        
        // Merge AI settings
        if other.ai.backend != "local" {
            self.ai.backend = other.ai.backend;
        }
        
        // Merge tool settings
        if !other.tools.slither.args.is_empty() {
            self.tools.slither.args = other.tools.slither.args;
        }
        
        Ok(self)
    }
    
    /// Validate configuration settings
    fn validate(&self) -> Result<()> {
        // Validate AI backend
        match self.ai.backend.as_str() {
            "openai" | "anthropic" | "local" => {},
            _ => return Err(BugForgeXError::config(format!("Invalid AI backend: {}", self.ai.backend))),
        }
        
        // Validate log level
        match self.general.log_level.as_str() {
            "trace" | "debug" | "info" | "warn" | "error" => {},
            _ => return Err(BugForgeXError::config(format!("Invalid log level: {}", self.general.log_level))),
        }
        
        // Validate timeout values
        if self.general.default_timeout == 0 {
            return Err(BugForgeXError::config("Default timeout must be greater than 0"));
        }
        
        // Validate confidence threshold
        if self.analysis.min_confidence < 0.0 || self.analysis.min_confidence > 1.0 {
            return Err(BugForgeXError::config("Minimum confidence must be between 0.0 and 1.0"));
        }
        
        // Validate AI temperature
        if self.ai.temperature < 0.0 || self.ai.temperature > 2.0 {
            return Err(BugForgeXError::config("AI temperature must be between 0.0 and 2.0"));
        }
        
        Ok(())
    }
    
    /// Get the configuration file path for the current user
    pub fn user_config_path() -> Option<PathBuf> {
        dirs::home_dir().map(|home| home.join(".config/bugforgex/config.toml"))
    }
    
    /// Initialize default configuration directory
    pub fn init_config_dir() -> Result<PathBuf> {
        let config_dir = dirs::home_dir()
            .ok_or_else(|| BugForgeXError::config("Could not determine home directory"))?
            .join(".config/bugforgex");
        
        std::fs::create_dir_all(&config_dir)
            .map_err(|e| BugForgeXError::config(format!("Failed to create config directory: {}", e)))?;
        
        Ok(config_dir)
    }
    
    /// Update a configuration value
    pub fn set_value(&mut self, key: &str, value: &str) -> Result<()> {
        match key {
            "general.log_level" => self.general.log_level = value.to_string(),
            "ai.backend" => self.ai.backend = value.to_string(),
            "ai.local.ollama_url" => self.ai.local.ollama_url = value.to_string(),
            "general.output_dir" => self.general.output_dir = PathBuf::from(value),
            "analysis.default_depth" => self.analysis.default_depth = value.to_string(),
            "reporting.default_format" => self.reporting.default_format = value.to_string(),
            _ => return Err(BugForgeXError::config(format!("Unknown configuration key: {}", key))),
        }
        
        self.validate()?;
        Ok(())
    }
    
    /// Get a configuration value as string
    pub fn get_value(&self, key: &str) -> Option<String> {
        match key {
            "general.log_level" => Some(self.general.log_level.clone()),
            "ai.backend" => Some(self.ai.backend.clone()),
            "ai.local.ollama_url" => Some(self.ai.local.ollama_url.clone()),
            "general.output_dir" => Some(self.general.output_dir.to_string_lossy().to_string()),
            "analysis.default_depth" => Some(self.analysis.default_depth.clone()),
            "reporting.default_format" => Some(self.reporting.default_format.clone()),
            _ => None,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        let home_dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        
        Self {
            general: GeneralConfig {
                log_level: "info".to_string(),
                max_concurrent_tasks: 4,
                output_dir: PathBuf::from("./output"),
                cache_dir: home_dir.join(".cache/bugforgex"),
                colored_output: true,
                default_timeout: 300,
            },
            ai: AiConfig {
                backend: "local".to_string(),
                openai: OpenAiConfig {
                    api_url: "https://api.openai.com/v1".to_string(),
                    model: "gpt-4".to_string(),
                    organization: None,
                    rate_limit: 60,
                },
                anthropic: AnthropicConfig {
                    api_url: "https://api.anthropic.com/v1".to_string(),
                    model: "claude-3-sonnet-20240229".to_string(),
                    rate_limit: 60,
                },
                local: LocalLlmConfig {
                    ollama_url: "http://localhost:11434".to_string(),
                    default_model: "codellama:7b".to_string(),
                    available_models: vec![
                        "codellama:7b".to_string(),
                        "codellama:13b".to_string(),
                        "mistral:7b".to_string(),
                        "llama2:7b".to_string(),
                    ],
                    gpu_acceleration: true,
                },
                enabled_by_default: false,
                max_tokens: 4000,
                temperature: 0.1,
            },
            networks: NetworkConfig {
                ethereum: BlockchainNetworkConfig {
                    explorer_url: "https://api.etherscan.io/api".to_string(),
                    rpc_url: "https://mainnet.infura.io/v3/YOUR_PROJECT_ID".to_string(),
                    rate_limit: 5,
                    timeout: 30,
                },
                polygon: BlockchainNetworkConfig {
                    explorer_url: "https://api.polygonscan.com/api".to_string(),
                    rpc_url: "https://polygon-mainnet.infura.io/v3/YOUR_PROJECT_ID".to_string(),
                    rate_limit: 5,
                    timeout: 30,
                },
                arbitrum: BlockchainNetworkConfig {
                    explorer_url: "https://api.arbiscan.io/api".to_string(),
                    rpc_url: "https://arbitrum-mainnet.infura.io/v3/YOUR_PROJECT_ID".to_string(),
                    rate_limit: 5,
                    timeout: 30,
                },
                optimism: BlockchainNetworkConfig {
                    explorer_url: "https://api-optimistic.etherscan.io/api".to_string(),
                    rpc_url: "https://optimism-mainnet.infura.io/v3/YOUR_PROJECT_ID".to_string(),
                    rate_limit: 5,
                    timeout: 30,
                },
                bsc: BlockchainNetworkConfig {
                    explorer_url: "https://api.bscscan.com/api".to_string(),
                    rpc_url: "https://bsc-dataseed.binance.org".to_string(),
                    rate_limit: 5,
                    timeout: 30,
                },
                solana: SolanaNetworkConfig {
                    rpc_url: "https://api.mainnet-beta.solana.com".to_string(),
                    explorer_url: "https://explorer.solana.com".to_string(),
                    rate_limit: 10,
                    timeout: 30,
                },
                github: GitHubConfig {
                    api_url: "https://api.github.com".to_string(),
                    rate_limit: 5000,
                    timeout: 30,
                },
            },
            tools: ToolsConfig {
                slither: SlitherConfig {
                    executable: "slither".to_string(),
                    args: vec!["--json".to_string(), "-".to_string()],
                    exclude_detectors: vec![],
                    include_detectors: vec![],
                    timeout: 300,
                },
                mythril: MythrilConfig {
                    executable: "myth".to_string(),
                    args: vec!["analyze".to_string(), "--output".to_string(), "json".to_string()],
                    timeout: 600,
                    max_depth: 22,
                    solver_timeout: 10000,
                },
                echidna: EchidnaConfig {
                    executable: "echidna-test".to_string(),
                    test_limit: 10000,
                    seq_len: 100,
                    shrink_limit: 5000,
                    timeout: 600,
                },
                custom: HashMap::new(),
            },
            analysis: AnalysisConfig {
                default_depth: "standard".to_string(),
                parallel_analysis: true,
                max_threads: 4,
                cache_results: true,
                cache_ttl: 3600,
                min_confidence: 0.5,
                severity_filters: vec![
                    "Critical".to_string(),
                    "High".to_string(),
                    "Medium".to_string(),
                    "Low".to_string(),
                ],
            },
            reporting: ReportingConfig {
                default_format: "markdown".to_string(),
                include_summary: true,
                template_dir: PathBuf::from("templates"),
                custom_templates: HashMap::new(),
                max_report_size: 100,
            },
        }
    }
}

/// Configuration builder for programmatic configuration creation
pub struct ConfigBuilder {
    config: Config,
}

impl ConfigBuilder {
    /// Create a new configuration builder
    pub fn new() -> Self {
        Self {
            config: Config::default(),
        }
    }
    
    /// Set AI backend
    pub fn ai_backend(mut self, backend: &str) -> Self {
        self.config.ai.backend = backend.to_string();
        self
    }
    
    /// Set log level
    pub fn log_level(mut self, level: &str) -> Self {
        self.config.general.log_level = level.to_string();
        self
    }
    
    /// Set output directory
    pub fn output_dir<P: Into<PathBuf>>(mut self, dir: P) -> Self {
        self.config.general.output_dir = dir.into();
        self
    }
    
    /// Enable colored output
    pub fn colored_output(mut self, enabled: bool) -> Self {
        self.config.general.colored_output = enabled;
        self
    }
    
    /// Set analysis depth
    pub fn analysis_depth(mut self, depth: &str) -> Self {
        self.config.analysis.default_depth = depth.to_string();
        self
    }
    
    /// Build the configuration
    pub fn build(self) -> Result<Config> {
        self.config.validate()?;
        Ok(self.config)
    }
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}
