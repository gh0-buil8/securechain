//! Contract parsing and AST analysis
//! 
//! This module handles parsing of smart contract source code
//! and extraction of relevant metadata for security analysis.

use anyhow::{anyhow, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::core::fetcher::ContractInfo;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedContract {
    pub name: String,
    pub source_code: String,
    pub functions: Vec<FunctionInfo>,
    pub state_variables: Vec<StateVariable>,
    pub modifiers: Vec<ModifierInfo>,
    pub events: Vec<EventInfo>,
    pub imports: Vec<String>,
    pub inheritance: Vec<String>,
    pub compiler_version: String,
    pub pragma_directives: Vec<String>,
    pub license: Option<String>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionInfo {
    pub name: String,
    pub visibility: String,
    pub state_mutability: String,
    pub parameters: Vec<Parameter>,
    pub return_parameters: Vec<Parameter>,
    pub modifiers: Vec<String>,
    pub line_number: usize,
    pub body: String,
    pub is_constructor: bool,
    pub is_fallback: bool,
    pub is_receive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateVariable {
    pub name: String,
    pub type_name: String,
    pub visibility: String,
    pub is_constant: bool,
    pub is_immutable: bool,
    pub initial_value: Option<String>,
    pub line_number: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModifierInfo {
    pub name: String,
    pub parameters: Vec<Parameter>,
    pub body: String,
    pub line_number: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventInfo {
    pub name: String,
    pub parameters: Vec<Parameter>,
    pub anonymous: bool,
    pub line_number: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    pub name: String,
    pub type_name: String,
    pub indexed: bool,
}

pub struct ContractParser {
    // Regex patterns for parsing
    function_pattern: Regex,
    state_var_pattern: Regex,
    modifier_pattern: Regex,
    event_pattern: Regex,
    import_pattern: Regex,
    pragma_pattern: Regex,
    license_pattern: Regex,
    inheritance_pattern: Regex,
}

impl ContractParser {
    /// Create a new contract parser
    pub fn new() -> Result<Self> {
        let function_pattern = Regex::new(
            r"function\s+(\w+)\s*\(([^)]*)\)\s*(external|public|internal|private)?\s*(view|pure|payable)?\s*(returns\s*\(([^)]*)\))?\s*(\w+\s*)*\s*\{"
        )?;
        
        let state_var_pattern = Regex::new(
            r"((?:uint|int|string|bool|bytes|address|mapping)\w*(?:\[\])*)\s+(public|private|internal)?\s*(constant|immutable)?\s*(\w+)(?:\s*=\s*([^;]+))?;"
        )?;
        
        let modifier_pattern = Regex::new(
            r"modifier\s+(\w+)\s*\(([^)]*)\)\s*\{"
        )?;
        
        let event_pattern = Regex::new(
            r"event\s+(\w+)\s*\(([^)]*)\)\s*(anonymous)?;"
        )?;
        
        let import_pattern = Regex::new(
            r#"import\s+(?:"([^"]+)"|'([^']+)')"#
        )?;
        
        let pragma_pattern = Regex::new(
            r"pragma\s+([^;]+);"
        )?;
        
        let license_pattern = Regex::new(
            r"//\s*SPDX-License-Identifier:\s*([^\r\n]+)"
        )?;
        
        let inheritance_pattern = Regex::new(
            r"contract\s+\w+\s+is\s+([^{]+)\s*\{"
        )?;

        Ok(Self {
            function_pattern,
            state_var_pattern,
            modifier_pattern,
            event_pattern,
            import_pattern,
            pragma_pattern,
            license_pattern,
            inheritance_pattern,
        })
    }

    /// Parse a contract from ContractInfo
    pub fn parse_contract(&self, contract_info: &ContractInfo) -> Result<ParsedContract> {
        let source_code = &contract_info.source_code;
        
        // Extract basic information
        let functions = self.extract_functions(source_code)?;
        let state_variables = self.extract_state_variables(source_code)?;
        let modifiers = self.extract_modifiers(source_code)?;
        let events = self.extract_events(source_code)?;
        let imports = self.extract_imports(source_code)?;
        let pragma_directives = self.extract_pragma_directives(source_code)?;
        let license = self.extract_license(source_code)?;
        let inheritance = self.extract_inheritance(source_code)?;

        Ok(ParsedContract {
            name: contract_info.name.clone(),
            source_code: source_code.clone(),
            functions,
            state_variables,
            modifiers,
            events,
            imports,
            inheritance,
            compiler_version: contract_info.compiler_version.clone(),
            pragma_directives,
            license,
            metadata: contract_info.metadata.clone(),
        })
    }

    /// Extract function information from source code
    fn extract_functions(&self, source_code: &str) -> Result<Vec<FunctionInfo>> {
        let mut functions = Vec::new();
        let lines: Vec<&str> = source_code.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            if let Some(captures) = self.function_pattern.captures(line) {
                let name = captures.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
                let params_str = captures.get(2).map(|m| m.as_str()).unwrap_or("");
                let visibility = captures.get(3).map(|m| m.as_str()).unwrap_or("internal").to_string();
                let state_mutability = captures.get(4).map(|m| m.as_str()).unwrap_or("").to_string();
                let returns_str = captures.get(6).map(|m| m.as_str()).unwrap_or("");

                let parameters = self.parse_parameters(params_str)?;
                let return_parameters = self.parse_parameters(returns_str)?;

                // Extract function body (simplified)
                let body = self.extract_function_body(source_code, line_num)?;

                functions.push(FunctionInfo {
                    name: name.clone(),
                    visibility,
                    state_mutability,
                    parameters,
                    return_parameters,
                    modifiers: Vec::new(), // TODO: Extract modifiers
                    line_number: line_num + 1,
                    body,
                    is_constructor: name == "constructor",
                    is_fallback: name == "fallback",
                    is_receive: name == "receive",
                });
            }
        }

        Ok(functions)
    }

    /// Extract state variables from source code
    fn extract_state_variables(&self, source_code: &str) -> Result<Vec<StateVariable>> {
        let mut state_variables = Vec::new();
        let lines: Vec<&str> = source_code.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            if let Some(captures) = self.state_var_pattern.captures(line) {
                let type_name = captures.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
                let visibility = captures.get(2).map(|m| m.as_str()).unwrap_or("internal").to_string();
                let mutability = captures.get(3).map(|m| m.as_str()).unwrap_or("");
                let name = captures.get(4).map(|m| m.as_str()).unwrap_or("").to_string();
                let initial_value = captures.get(5).map(|m| m.as_str().to_string());

                state_variables.push(StateVariable {
                    name,
                    type_name,
                    visibility,
                    is_constant: mutability == "constant",
                    is_immutable: mutability == "immutable",
                    initial_value,
                    line_number: line_num + 1,
                });
            }
        }

        Ok(state_variables)
    }

    /// Extract modifiers from source code
    fn extract_modifiers(&self, source_code: &str) -> Result<Vec<ModifierInfo>> {
        let mut modifiers = Vec::new();
        let lines: Vec<&str> = source_code.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            if let Some(captures) = self.modifier_pattern.captures(line) {
                let name = captures.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
                let params_str = captures.get(2).map(|m| m.as_str()).unwrap_or("");
                let parameters = self.parse_parameters(params_str)?;

                // Extract modifier body (simplified)
                let body = self.extract_modifier_body(source_code, line_num)?;

                modifiers.push(ModifierInfo {
                    name,
                    parameters,
                    body,
                    line_number: line_num + 1,
                });
            }
        }

        Ok(modifiers)
    }

    /// Extract events from source code
    fn extract_events(&self, source_code: &str) -> Result<Vec<EventInfo>> {
        let mut events = Vec::new();
        let lines: Vec<&str> = source_code.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            if let Some(captures) = self.event_pattern.captures(line) {
                let name = captures.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
                let params_str = captures.get(2).map(|m| m.as_str()).unwrap_or("");
                let anonymous = captures.get(3).is_some();
                let parameters = self.parse_parameters(params_str)?;

                events.push(EventInfo {
                    name,
                    parameters,
                    anonymous,
                    line_number: line_num + 1,
                });
            }
        }

        Ok(events)
    }

    /// Extract import statements
    fn extract_imports(&self, source_code: &str) -> Result<Vec<String>> {
        let mut imports = Vec::new();

        for captures in self.import_pattern.captures_iter(source_code) {
            let import_path = captures.get(1)
                .or_else(|| captures.get(2))
                .map(|m| m.as_str())
                .unwrap_or("")
                .to_string();
            
            if !import_path.is_empty() {
                imports.push(import_path);
            }
        }

        Ok(imports)
    }

    /// Extract pragma directives
    fn extract_pragma_directives(&self, source_code: &str) -> Result<Vec<String>> {
        let mut pragmas = Vec::new();

        for captures in self.pragma_pattern.captures_iter(source_code) {
            let pragma = captures.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            pragmas.push(pragma);
        }

        Ok(pragmas)
    }

    /// Extract license information
    fn extract_license(&self, source_code: &str) -> Result<Option<String>> {
        if let Some(captures) = self.license_pattern.captures(source_code) {
            let license = captures.get(1).map(|m| m.as_str().trim().to_string());
            return Ok(license);
        }
        Ok(None)
    }

    /// Extract inheritance information
    fn extract_inheritance(&self, source_code: &str) -> Result<Vec<String>> {
        let mut inheritance = Vec::new();

        for captures in self.inheritance_pattern.captures_iter(source_code) {
            let inherit_str = captures.get(1).map(|m| m.as_str()).unwrap_or("");
            let parents: Vec<String> = inherit_str
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            inheritance.extend(parents);
        }

        Ok(inheritance)
    }

    /// Parse function parameters
    fn parse_parameters(&self, params_str: &str) -> Result<Vec<Parameter>> {
        let mut parameters = Vec::new();

        if params_str.trim().is_empty() {
            return Ok(parameters);
        }

        for param in params_str.split(',') {
            let param = param.trim();
            if param.is_empty() {
                continue;
            }

            let parts: Vec<&str> = param.split_whitespace().collect();
            if parts.len() >= 2 {
                let type_name = parts[0].to_string();
                let name = parts[1].to_string();
                let indexed = param.contains("indexed");

                parameters.push(Parameter {
                    name,
                    type_name,
                    indexed,
                });
            }
        }

        Ok(parameters)
    }

    /// Extract function body (simplified implementation)
    fn extract_function_body(&self, source_code: &str, start_line: usize) -> Result<String> {
        let lines: Vec<&str> = source_code.lines().collect();
        let mut body = String::new();
        let mut brace_count = 0;
        let mut started = false;

        for (i, line) in lines.iter().enumerate().skip(start_line) {
            for ch in line.chars() {
                if ch == '{' {
                    brace_count += 1;
                    started = true;
                } else if ch == '}' {
                    brace_count -= 1;
                }
            }

            if started {
                body.push_str(line);
                body.push('\n');
            }

            if started && brace_count == 0 {
                break;
            }
        }

        Ok(body)
    }

    /// Extract modifier body (simplified implementation)
    fn extract_modifier_body(&self, source_code: &str, start_line: usize) -> Result<String> {
        // Similar to extract_function_body but for modifiers
        self.extract_function_body(source_code, start_line)
    }
}

impl Default for ContractParser {
    fn default() -> Self {
        Self::new().expect("Failed to create contract parser")
    }
}
