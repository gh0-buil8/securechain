//! Report generator for creating comprehensive security audit reports
//! 
//! This module provides functionality to generate reports in various formats
//! including Markdown, HTML, PDF, and JSON.

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use crate::core::analyzer::{AnalysisResults, AnalysisMetrics, AnalysisSummary};
use crate::report::vulnerability::{Vulnerability, VulnerabilityCategory};
use crate::utils::config::Config;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComprehensiveReport {
    pub metadata: ReportMetadata,
    pub executive_summary: ExecutiveSummary,
    pub vulnerability_analysis: VulnerabilityAnalysis,
    pub recommendations: Vec<Recommendation>,
    pub technical_details: TechnicalDetails,
    pub appendices: Vec<Appendix>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    pub report_id: String,
    pub generated_at: DateTime<Utc>,
    pub version: String,
    pub contract_name: String,
    pub analysis_tools: Vec<String>,
    pub report_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutiveSummary {
    pub overall_risk_level: String,
    pub total_vulnerabilities: usize,
    pub critical_findings: usize,
    pub high_risk_findings: usize,
    pub medium_risk_findings: usize,
    pub low_risk_findings: usize,
    pub security_score: f64,
    pub key_findings: Vec<String>,
    pub recommendations_summary: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityAnalysis {
    pub vulnerabilities: Vec<Vulnerability>,
    pub category_breakdown: HashMap<String, usize>,
    pub severity_distribution: HashMap<String, usize>,
    pub tool_findings: HashMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub id: String,
    pub title: String,
    pub description: String,
    pub priority: String,
    pub effort: String,
    pub impact: String,
    pub related_vulnerabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechnicalDetails {
    pub analysis_metrics: AnalysisMetrics,
    pub coverage_report: CoverageReport,
    pub tool_configurations: HashMap<String, String>,
    pub analysis_duration: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageReport {
    pub lines_analyzed: usize,
    pub functions_analyzed: usize,
    pub coverage_percentage: f64,
    pub uncovered_areas: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Appendix {
    pub title: String,
    pub content: String,
    pub appendix_type: String,
}

pub struct ReportGenerator {
    config: Config,
}

impl ReportGenerator {
    /// Create a new report generator
    pub fn new(config: Config) -> Self {
        Self { config }
    }
    
    /// Generate executive summary report
    pub fn generate_executive_summary(
        &self,
        results: &crate::core::analyzer::AnalysisResults,
        probes: &[crate::core::analyzer::CreativeProbe],
    ) -> Result<String> {
        let mut report = String::new();
        
        // Header
        report.push_str(&format!(r#"
# Executive Security Audit Summary

**Project:** {}  
**Audit Date:** {}  
**Auditor:** SecureChain Perfect Audit  
**Version:** {}

## 🎯 Executive Overview

This security audit was conducted using SecureChain's comprehensive analysis framework, combining static analysis, dynamic fuzzing, and AI-powered vulnerability detection to identify potential security risks in the smart contract codebase.

## 📊 Key Findings

| Metric | Value |
|--------|-------|
| **Total Vulnerabilities** | {} |
| **Critical Severity** | {} |
| **High Severity** | {} |
| **Medium Severity** | {} |
| **Low Severity** | {} |
| **Security Score** | {:.1}/100 |
| **Creative Probes** | {} |

## 🚨 Critical Issues Summary

"#, 
            results.contract_name,
            chrono::Utc::now().format("%Y-%m-%d"),
            env!("CARGO_PKG_VERSION"),
            results.vulnerabilities.len(),
            results.analysis_summary.critical_count,
            results.analysis_summary.high_count,
            results.analysis_summary.medium_count,
            results.analysis_summary.low_count,
            results.metrics.security_score,
            probes.len()
        ));
        
        // Critical issues
        let critical_issues: Vec<_> = results.vulnerabilities.iter()
            .filter(|v| v.severity == "Critical")
            .collect();
            
        if critical_issues.is_empty() {
            report.push_str("✅ **No critical vulnerabilities found.**\n\n");
        } else {
            for (i, issue) in critical_issues.iter().enumerate() {
                report.push_str(&format!(
                    "{}. **{}**\n   - Impact: High financial/security risk\n   - Status: Requires immediate attention\n\n",
                    i + 1, issue.title
                ));
            }
        }
        
        // Business impact
        report.push_str(&format!(r#"
## 💼 Business Impact Assessment

**Risk Level:** {}

**Financial Risk:** {}

**Recommended Actions:**
1. Address all critical and high severity vulnerabilities before deployment
2. Implement comprehensive testing framework
3. Consider bug bounty program for ongoing security
4. Schedule regular security audits

## 🔧 Remediation Timeline

| Priority | Timeframe | Action Items |
|----------|-----------|--------------|
| **Immediate** | 1-3 days | Fix critical vulnerabilities |
| **High** | 1-2 weeks | Address high severity issues |
| **Medium** | 2-4 weeks | Resolve medium severity issues |
| **Low** | Next release | Address low priority items |

## 📈 Security Maturity Recommendations

1. **Code Quality:** Implement strict coding standards and peer review
2. **Testing:** Achieve >90% test coverage with edge case testing
3. **Monitoring:** Deploy runtime monitoring and alerting systems
4. **Incident Response:** Establish security incident response procedures

---

*This executive summary provides a high-level overview. See the technical report for detailed findings and remediation guidance.*
"#,
            if results.analysis_summary.critical_count > 0 { "🔴 HIGH" }
            else if results.analysis_summary.high_count > 0 { "🟠 MEDIUM" }
            else { "🟢 LOW" },
            
            if results.analysis_summary.critical_count > 0 { "Potential for significant financial loss" }
            else { "Limited financial exposure" }
        ));
        
        Ok(report)
    }
    
    /// Generate technical report
    pub fn generate_technical_report(
        &self,
        results: &crate::core::analyzer::AnalysisResults,
        probes: &[crate::core::analyzer::CreativeProbe],
    ) -> Result<String> {
        let mut report = String::new();
        
        // Header
        report.push_str(&format!(r#"
# Technical Security Audit Report

**Project:** {}  
**Audit Date:** {}  
**Analysis Duration:** {:.2} seconds  
**Tools Used:** {}

## 🔍 Methodology

This comprehensive security audit employed multiple analysis techniques:

1. **Static Analysis:** Code review using Slither and Mythril
2. **Dynamic Analysis:** Property-based fuzzing with Echidna
3. **AI Analysis:** Creative vulnerability discovery using large language models
4. **Manual Review:** Expert analysis of complex logic and edge cases

## 📋 Detailed Findings

"#,
            results.contract_name,
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
            results.analysis_summary.analysis_duration,
            results.analysis_summary.tools_used.join(", ")
        ));
        
        // Group and display vulnerabilities
        let mut by_severity = std::collections::HashMap::new();
        for vuln in &results.vulnerabilities {
            by_severity.entry(&vuln.severity).or_insert(Vec::new()).push(vuln);
        }
        
        for severity in &["Critical", "High", "Medium", "Low", "Info"] {
            if let Some(vulns) = by_severity.get(*severity) {
                report.push_str(&format!("\n### {} Severity Issues ({})\n\n", severity, vulns.len()));
                
                for (i, vuln) in vulns.iter().enumerate() {
                    report.push_str(&format!(r#"
#### {}.{} {}

**Severity:** {}  
**Category:** {:?}  
**File:** {}  
**Line:** {}  
**Tool:** {}  
**Confidence:** {:.1}%

**Description:**
{}

**Impact:**
This vulnerability could potentially lead to [describe specific impact based on category].

**Recommendation:**
{}

**References:**
{}

**CWE:** {}

---
"#,
                        severity,
                        i + 1,
                        vuln.title,
                        vuln.severity,
                        vuln.category,
                        vuln.file_path,
                        vuln.line_number.unwrap_or(0),
                        vuln.tool,
                        vuln.confidence * 100.0,
                        vuln.description,
                        vuln.recommendation.as_ref().unwrap_or(&"Review and fix this issue".to_string()),
                        vuln.references.join(", "),
                        vuln.cwe_id.as_ref().unwrap_or(&"N/A".to_string())
                    ));
                    
                    if let Some(code) = &vuln.code_snippet {
                        report.push_str(&format!("**Code Snippet:**\n```solidity\n{}\n```\n\n", code));
                    }
                }
            }
        }
        
        // Creative probes section
        if !probes.is_empty() {
            report.push_str("\n## 🧠 AI-Generated Creative Attack Probes\n\n");
            
            for (i, probe) in probes.iter().enumerate() {
                report.push_str(&format!(r#"
### Creative Probe #{}: {}

**Severity:** {}  
**Confidence:** {:.1}%

**Attack Vector:**
{}

**Potential Impact:**
{}

**Description:**
{}
"#,
                    i + 1,
                    probe.title,
                    probe.severity,
                    probe.confidence * 100.0,
                    probe.attack_vector,
                    probe.impact,
                    probe.description
                ));
                
                if let Some(poc) = &probe.proof_of_concept {
                    report.push_str(&format!("\n**Proof of Concept:**\n```solidity\n{}\n```\n", poc));
                }
                
                if let Some(fix) = &probe.recommended_fix {
                    report.push_str(&format!("\n**Recommended Fix:**\n{}\n", fix));
                }
                
                report.push_str("\n---\n");
            }
        }
        
        // Analysis metrics
        report.push_str(&format!(r#"
## 📊 Analysis Metrics

| Metric | Value |
|--------|-------|
| Lines of Code | {} |
| Functions Analyzed | {} |
| Complexity Score | {:.2} |
| Security Score | {:.2}/100 |
| Coverage Percentage | {:.1}% |

## 🔧 Remediation Checklist

### Immediate Actions Required
- [ ] Review and fix all critical severity vulnerabilities
- [ ] Implement proper access controls where missing
- [ ] Add reentrancy guards to external functions
- [ ] Validate all user inputs and external calls

### Security Enhancements
- [ ] Implement circuit breakers for emergency situations
- [ ] Add comprehensive event logging
- [ ] Use established security patterns (OpenZeppelin)
- [ ] Implement proper error handling

### Testing & Deployment
- [ ] Write comprehensive unit tests
- [ ] Perform integration testing
- [ ] Deploy to testnet for additional validation
- [ ] Set up monitoring and alerting

## 📚 Additional Resources

- [OpenZeppelin Security Guidelines](https://docs.openzeppelin.com/contracts/4.x/security)
- [Consensys Smart Contract Security Best Practices](https://consensys.github.io/smart-contract-best-practices/)
- [OWASP Smart Contract Security](https://owasp.org/www-project-smart-contract-security/)

---

*Report generated by SecureChain v{} on {}*
"#,
            results.metrics.lines_of_code,
            results.metrics.functions_analyzed,
            results.metrics.complexity_score,
            results.metrics.security_score,
            results.analysis_summary.coverage_percentage,
            env!("CARGO_PKG_VERSION"),
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        ));
        
        Ok(report)
    }

    /// Generate a comprehensive report
    pub async fn generate_comprehensive_report(
        &self,
        results_path: &Path,
        format: &str,
        include_summary: bool,
    ) -> Result<String> {
        // Load analysis results
        let results = self.load_analysis_results(results_path)?;
        
        // Generate comprehensive report
        let report = self.create_comprehensive_report(&results, include_summary)?;
        
        // Format the report
        match format {
            "markdown" => self.generate_markdown_report(&report),
            "html" => self.generate_html_report(&report),
            "json" => self.generate_json_report(&report),
            "pdf" => self.generate_pdf_report(&report),
            _ => Err(anyhow!("Unsupported report format: {}", format)),
        }
    }

    /// Generate a markdown report from analysis results
    pub fn generate_markdown_report_from_results(&self, results: &AnalysisResults) -> Result<String> {
        let report = self.create_comprehensive_report(results, true)?;
        self.generate_markdown_report(&report)
    }

    /// Load analysis results from file
    fn load_analysis_results(&self, path: &Path) -> Result<AnalysisResults> {
        let content = std::fs::read_to_string(path)?;
        let results: AnalysisResults = serde_json::from_str(&content)?;
        Ok(results)
    }

    /// Create a comprehensive report from analysis results
    fn create_comprehensive_report(&self, results: &AnalysisResults, include_summary: bool) -> Result<ComprehensiveReport> {
        let metadata = self.create_report_metadata(results)?;
        let vulnerability_analysis = self.create_vulnerability_analysis(&results.vulnerabilities)?;
        let recommendations = self.create_recommendations(&results.vulnerabilities, &results.recommendations)?;
        let technical_details = self.create_technical_details(&results.metrics, results.analysis_summary.analysis_duration)?;
        let appendices = self.create_appendices(results)?;

        let executive_summary = if include_summary {
            self.create_executive_summary(results, &vulnerability_analysis)?
        } else {
            ExecutiveSummary {
                overall_risk_level: "Not Calculated".to_string(),
                total_vulnerabilities: results.vulnerabilities.len(),
                critical_findings: 0,
                high_risk_findings: 0,
                medium_risk_findings: 0,
                low_risk_findings: 0,
                security_score: results.metrics.security_score,
                key_findings: Vec::new(),
                recommendations_summary: Vec::new(),
            }
        };

        Ok(ComprehensiveReport {
            metadata,
            executive_summary,
            vulnerability_analysis,
            recommendations,
            technical_details,
            appendices,
        })
    }

    /// Create report metadata
    fn create_report_metadata(&self, results: &AnalysisResults) -> Result<ReportMetadata> {
        Ok(ReportMetadata {
            report_id: uuid::Uuid::new_v4().to_string(),
            generated_at: Utc::now(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            contract_name: results.contract_name.clone(),
            analysis_tools: results.analysis_summary.tools_used.clone(),
            report_type: "Security Audit Report".to_string(),
        })
    }

    /// Create executive summary
    fn create_executive_summary(&self, results: &AnalysisResults, vulnerability_analysis: &VulnerabilityAnalysis) -> Result<ExecutiveSummary> {
        let critical_findings = vulnerability_analysis.severity_distribution.get("Critical").unwrap_or(&0);
        let high_risk_findings = vulnerability_analysis.severity_distribution.get("High").unwrap_or(&0);
        let medium_risk_findings = vulnerability_analysis.severity_distribution.get("Medium").unwrap_or(&0);
        let low_risk_findings = vulnerability_analysis.severity_distribution.get("Low").unwrap_or(&0);

        let overall_risk_level = match (critical_findings, high_risk_findings) {
            (c, _) if *c > 0 => "Critical",
            (_, h) if *h > 0 => "High",
            _ if *medium_risk_findings > 0 => "Medium",
            _ if *low_risk_findings > 0 => "Low",
            _ => "Minimal",
        }.to_string();

        let key_findings = self.extract_key_findings(&results.vulnerabilities);
        let recommendations_summary = results.recommendations.iter().take(3).cloned().collect();

        Ok(ExecutiveSummary {
            overall_risk_level,
            total_vulnerabilities: results.vulnerabilities.len(),
            critical_findings: *critical_findings,
            high_risk_findings: *high_risk_findings,
            medium_risk_findings: *medium_risk_findings,
            low_risk_findings: *low_risk_findings,
            security_score: results.metrics.security_score,
            key_findings,
            recommendations_summary,
        })
    }

    /// Create vulnerability analysis
    fn create_vulnerability_analysis(&self, vulnerabilities: &[Vulnerability]) -> Result<VulnerabilityAnalysis> {
        let mut category_breakdown = HashMap::new();
        let mut severity_distribution = HashMap::new();
        let mut tool_findings = HashMap::new();

        for vuln in vulnerabilities {
            // Count by category
            let category = format!("{:?}", vuln.category);
            *category_breakdown.entry(category).or_insert(0) += 1;

            // Count by severity
            *severity_distribution.entry(vuln.severity.clone()).or_insert(0) += 1;

            // Count by tool
            *tool_findings.entry(vuln.tool.clone()).or_insert(0) += 1;
        }

        Ok(VulnerabilityAnalysis {
            vulnerabilities: vulnerabilities.to_vec(),
            category_breakdown,
            severity_distribution,
            tool_findings,
        })
    }

    /// Create recommendations
    fn create_recommendations(&self, vulnerabilities: &[Vulnerability], basic_recommendations: &[String]) -> Result<Vec<Recommendation>> {
        let mut recommendations = Vec::new();

        // Generate specific recommendations based on vulnerabilities
        let mut processed_categories = std::collections::HashSet::new();

        for vuln in vulnerabilities {
            let category_key = format!("{:?}", vuln.category);
            if !processed_categories.contains(&category_key) {
                processed_categories.insert(category_key.clone());

                let recommendation = self.create_category_recommendation(&vuln.category, vulnerabilities);
                recommendations.push(recommendation);
            }
        }

        // Add general recommendations
        for (i, rec) in basic_recommendations.iter().enumerate() {
            recommendations.push(Recommendation {
                id: format!("REC-{:03}", i + 100),
                title: format!("General Recommendation {}", i + 1),
                description: rec.clone(),
                priority: "Medium".to_string(),
                effort: "Medium".to_string(),
                impact: "Medium".to_string(),
                related_vulnerabilities: Vec::new(),
            });
        }

        Ok(recommendations)
    }

    /// Create category-specific recommendation
    fn create_category_recommendation(&self, category: &VulnerabilityCategory, vulnerabilities: &[Vulnerability]) -> Recommendation {
        let related_vulns: Vec<String> = vulnerabilities
            .iter()
            .filter(|v| v.category == *category)
            .map(|v| v.id.clone())
            .collect();

        match category {
            VulnerabilityCategory::Reentrancy => Recommendation {
                id: "REC-001".to_string(),
                title: "Implement Reentrancy Protection".to_string(),
                description: "Use reentrancy guards or checks-effects-interactions pattern to prevent reentrancy attacks.".to_string(),
                priority: "High".to_string(),
                effort: "Medium".to_string(),
                impact: "High".to_string(),
                related_vulnerabilities: related_vulns,
            },
            VulnerabilityCategory::AccessControl => Recommendation {
                id: "REC-002".to_string(),
                title: "Strengthen Access Control".to_string(),
                description: "Implement proper access control mechanisms using role-based permissions.".to_string(),
                priority: "High".to_string(),
                effort: "High".to_string(),
                impact: "High".to_string(),
                related_vulnerabilities: related_vulns,
            },
            VulnerabilityCategory::IntegerOverflow => Recommendation {
                id: "REC-003".to_string(),
                title: "Use Safe Math Operations".to_string(),
                description: "Implement SafeMath library or use Solidity 0.8+ built-in overflow protection.".to_string(),
                priority: "Medium".to_string(),
                effort: "Low".to_string(),
                impact: "Medium".to_string(),
                related_vulnerabilities: related_vulns,
            },
            VulnerabilityCategory::UnhandledExceptions => Recommendation {
                id: "REC-004".to_string(),
                title: "Improve Error Handling".to_string(),
                description: "Implement proper error handling for all external calls and operations.".to_string(),
                priority: "Medium".to_string(),
                effort: "Medium".to_string(),
                impact: "Medium".to_string(),
                related_vulnerabilities: related_vulns,
            },
            _ => Recommendation {
                id: "REC-999".to_string(),
                title: format!("Address {:?} Issues", category),
                description: format!("Review and address all {:?} related vulnerabilities.", category),
                priority: "Medium".to_string(),
                effort: "Medium".to_string(),
                impact: "Medium".to_string(),
                related_vulnerabilities: related_vulns,
            },
        }
    }

    /// Create technical details
    fn create_technical_details(&self, metrics: &AnalysisMetrics, duration: f64) -> Result<TechnicalDetails> {
        let coverage_report = CoverageReport {
            lines_analyzed: metrics.lines_of_code,
            functions_analyzed: metrics.functions_analyzed,
            coverage_percentage: 85.0, // Mock value
            uncovered_areas: vec!["External library interactions".to_string()],
        };

        let mut tool_configurations = HashMap::new();
        tool_configurations.insert("slither".to_string(), "Default configuration".to_string());
        tool_configurations.insert("mythril".to_string(), "Deep analysis mode".to_string());

        Ok(TechnicalDetails {
            analysis_metrics: metrics.clone(),
            coverage_report,
            tool_configurations,
            analysis_duration: duration,
        })
    }

    /// Create appendices
    fn create_appendices(&self, results: &AnalysisResults) -> Result<Vec<Appendix>> {
        let mut appendices = Vec::new();

        // Add tool output appendix
        appendices.push(Appendix {
            title: "Tool Configurations".to_string(),
            content: format!("Analysis performed using: {}", results.analysis_summary.tools_used.join(", ")),
            appendix_type: "configuration".to_string(),
        });

        // Add metrics appendix
        appendices.push(Appendix {
            title: "Analysis Metrics".to_string(),
            content: format!("Security Score: {:.2}\nComplexity Score: {:.2}\nLines of Code: {}", 
                results.metrics.security_score, 
                results.metrics.complexity_score, 
                results.metrics.lines_of_code),
            appendix_type: "metrics".to_string(),
        });

        Ok(appendices)
    }

    /// Extract key findings from vulnerabilities
    fn extract_key_findings(&self, vulnerabilities: &[Vulnerability]) -> Vec<String> {
        let mut key_findings = Vec::new();

        // Get critical and high severity findings
        let critical_findings: Vec<&Vulnerability> = vulnerabilities
            .iter()
            .filter(|v| v.severity == "Critical")
            .collect();

        let high_findings: Vec<&Vulnerability> = vulnerabilities
            .iter()
            .filter(|v| v.severity == "High")
            .collect();

        // Add top critical findings
        for finding in critical_findings.iter().take(3) {
            key_findings.push(format!("🔴 Critical: {}", finding.title));
        }

        // Add top high findings
        for finding in high_findings.iter().take(2) {
            key_findings.push(format!("🟠 High: {}", finding.title));
        }

        if key_findings.is_empty() {
            key_findings.push("No critical or high-severity vulnerabilities found.".to_string());
        }

        key_findings
    }

    /// Generate markdown report
    fn generate_markdown_report(&self, report: &ComprehensiveReport) -> Result<String> {
        let mut markdown = String::new();

        // Title and metadata
        markdown.push_str(&format!("# Security Audit Report: {}\n\n", report.metadata.contract_name));
        markdown.push_str(&format!("**Report ID:** {}\n", report.metadata.report_id));
        markdown.push_str(&format!("**Generated:** {}\n", report.metadata.generated_at.format("%Y-%m-%d %H:%M:%S UTC")));
        markdown.push_str(&format!("**Version:** {}\n", report.metadata.version));
        markdown.push_str(&format!("**Tools Used:** {}\n\n", report.metadata.analysis_tools.join(", ")));

        // Executive Summary
        markdown.push_str("## Executive Summary\n\n");
        markdown.push_str(&format!("**Overall Risk Level:** {}\n", report.executive_summary.overall_risk_level));
        markdown.push_str(&format!("**Security Score:** {:.2}/100\n", report.executive_summary.security_score));
        markdown.push_str(&format!("**Total Vulnerabilities:** {}\n\n", report.executive_summary.total_vulnerabilities));

        markdown.push_str("### Severity Distribution\n\n");
        markdown.push_str(&format!("- 🔴 Critical: {}\n", report.executive_summary.critical_findings));
        markdown.push_str(&format!("- 🟠 High: {}\n", report.executive_summary.high_risk_findings));
        markdown.push_str(&format!("- 🟡 Medium: {}\n", report.executive_summary.medium_risk_findings));
        markdown.push_str(&format!("- 🟢 Low: {}\n\n", report.executive_summary.low_risk_findings));

        // Key Findings
        if !report.executive_summary.key_findings.is_empty() {
            markdown.push_str("### Key Findings\n\n");
            for finding in &report.executive_summary.key_findings {
                markdown.push_str(&format!("- {}\n", finding));
            }
            markdown.push_str("\n");
        }

        // Vulnerabilities
        markdown.push_str("## Vulnerability Analysis\n\n");
        
        // Group vulnerabilities by severity
        let mut critical = Vec::new();
        let mut high = Vec::new();
        let mut medium = Vec::new();
        let mut low = Vec::new();
        let mut info = Vec::new();

        for vuln in &report.vulnerability_analysis.vulnerabilities {
            match vuln.severity.as_str() {
                "Critical" => critical.push(vuln),
                "High" => high.push(vuln),
                "Medium" => medium.push(vuln),
                "Low" => low.push(vuln),
                _ => info.push(vuln),
            }
        }

        self.add_vulnerability_section(&mut markdown, "Critical", &critical, "🔴")?;
        self.add_vulnerability_section(&mut markdown, "High", &high, "🟠")?;
        self.add_vulnerability_section(&mut markdown, "Medium", &medium, "🟡")?;
        self.add_vulnerability_section(&mut markdown, "Low", &low, "🟢")?;
        self.add_vulnerability_section(&mut markdown, "Informational", &info, "🔵")?;

        // Recommendations
        markdown.push_str("## Recommendations\n\n");
        for (i, rec) in report.recommendations.iter().enumerate() {
            markdown.push_str(&format!("### {}. {}\n\n", i + 1, rec.title));
            markdown.push_str(&format!("**Priority:** {}\n", rec.priority));
            markdown.push_str(&format!("**Effort:** {}\n", rec.effort));
            markdown.push_str(&format!("**Impact:** {}\n\n", rec.impact));
            markdown.push_str(&format!("{}\n\n", rec.description));
        }

        // Technical Details
        markdown.push_str("## Technical Details\n\n");
        markdown.push_str(&format!("**Analysis Duration:** {:.2} seconds\n", report.technical_details.analysis_duration));
        markdown.push_str(&format!("**Lines of Code:** {}\n", report.technical_details.analysis_metrics.lines_of_code));
        markdown.push_str(&format!("**Functions Analyzed:** {}\n", report.technical_details.analysis_metrics.functions_analyzed));
        markdown.push_str(&format!("**Complexity Score:** {:.2}\n\n", report.technical_details.analysis_metrics.complexity_score));

        // Appendices
        if !report.appendices.is_empty() {
            markdown.push_str("## Appendices\n\n");
            for appendix in &report.appendices {
                markdown.push_str(&format!("### {}\n\n", appendix.title));
                markdown.push_str(&format!("{}\n\n", appendix.content));
            }
        }

        Ok(markdown)
    }

    /// Add vulnerability section to markdown
    fn add_vulnerability_section(&self, markdown: &mut String, severity: &str, vulnerabilities: &[&Vulnerability], icon: &str) -> Result<()> {
        if vulnerabilities.is_empty() {
            return Ok(());
        }

        markdown.push_str(&format!("### {} {} Vulnerabilities\n\n", icon, severity));

        for (i, vuln) in vulnerabilities.iter().enumerate() {
            markdown.push_str(&format!("#### {}.{} {}\n\n", severity.chars().next().unwrap(), i + 1, vuln.title));
            markdown.push_str(&format!("**Description:** {}\n\n", vuln.description));
            markdown.push_str(&format!("**File:** {}\n", vuln.file_path));
            if let Some(line) = vuln.line_number {
                markdown.push_str(&format!("**Line:** {}\n", line));
            }
            markdown.push_str(&format!("**Tool:** {}\n", vuln.tool));
            markdown.push_str(&format!("**Confidence:** {:.2}\n\n", vuln.confidence));

            if let Some(code) = &vuln.code_snippet {
                markdown.push_str("**Code Snippet:**\n");
                markdown.push_str("```solidity\n");
                markdown.push_str(code);
                markdown.push_str("\n```\n\n");
            }

            if let Some(recommendation) = &vuln.recommendation {
                markdown.push_str(&format!("**Recommendation:** {}\n\n", recommendation));
            }

            if !vuln.references.is_empty() {
                markdown.push_str("**References:**\n");
                for reference in &vuln.references {
                    markdown.push_str(&format!("- {}\n", reference));
                }
                markdown.push_str("\n");
            }

            markdown.push_str("---\n\n");
        }

        Ok(())
    }

    /// Generate HTML report
    fn generate_html_report(&self, report: &ComprehensiveReport) -> Result<String> {
        let markdown = self.generate_markdown_report(report)?;
        
        // Convert markdown to HTML (simplified implementation)
        let html = format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>Security Audit Report - {}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        h2 {{ color: #666; border-bottom: 2px solid #eee; }}
        h3 {{ color: #888; }}
        .severity-critical {{ color: #dc3545; }}
        .severity-high {{ color: #fd7e14; }}
        .severity-medium {{ color: #ffc107; }}
        .severity-low {{ color: #28a745; }}
        .code {{ background-color: #f8f9fa; padding: 10px; border-radius: 4px; }}
        .vulnerability {{ border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }}
    </style>
</head>
<body>
    <pre>{}</pre>
</body>
</html>"#,
            report.metadata.contract_name,
            markdown
        );

        Ok(html)
    }

    /// Generate JSON report
    fn generate_json_report(&self, report: &ComprehensiveReport) -> Result<String> {
        let json = serde_json::to_string_pretty(report)?;
        Ok(json)
    }

    /// Generate PDF report (placeholder implementation)
    fn generate_pdf_report(&self, report: &ComprehensiveReport) -> Result<String> {
        // This would require a PDF generation library like wkhtmltopdf or similar
        // For now, return HTML that can be converted to PDF
        self.generate_html_report(report)
    }
}

impl Default for ReportGenerator {
    fn default() -> Self {
        Self::new(Config::default())
    }
}
