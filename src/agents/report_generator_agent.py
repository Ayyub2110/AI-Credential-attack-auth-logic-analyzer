"""
Report Generator Agent

Responsibilities:
- Compile findings from all agents
- Generate structured security reports
- Provide remediation recommendations
- Create executive summaries
- Export in multiple formats (JSON, Markdown, HTML)
"""

from typing import Dict, List, Optional
from datetime import datetime
from crewai import Agent


class PentestReportGenerator:
    """
    Professional penetration testing report generator.
    
    Generates client-ready Markdown reports from aggregated agent findings.
    """
    
    @staticmethod
    def generate_markdown_report(
        auth_logic_findings: Optional[Dict] = None,
        username_enum_findings: Optional[Dict] = None,
        bruteforce_findings: Optional[Dict] = None,
        mfa_logic_findings: Optional[Dict] = None,
        token_abuse_findings: Optional[Dict] = None,
        metadata: Optional[Dict] = None
    ) -> str:
        """
        Generate a comprehensive penetration testing report in Markdown format.
        
        Args:
            auth_logic_findings: Findings from AuthLogicAgent
            username_enum_findings: Findings from UsernameEnumAgent
            bruteforce_findings: Findings from BruteforceStrategyAgent
            mfa_logic_findings: Findings from MFALogicAgent
            token_abuse_findings: Findings from TokenAbuseAgent
            metadata: Additional metadata (target, tester name, etc.)
        
        Returns:
            str: Markdown-formatted report
        """
        metadata = metadata or {}
        report_parts = []
        
        # Header
        report_parts.append(PentestReportGenerator._generate_header(metadata))
        
        # Executive Summary
        report_parts.append(PentestReportGenerator._generate_executive_summary(
            auth_logic_findings,
            username_enum_findings,
            bruteforce_findings,
            mfa_logic_findings,
            token_abuse_findings
        ))
        
        # Authentication Flow Summary
        if auth_logic_findings:
            report_parts.append(PentestReportGenerator._generate_auth_flow_summary(auth_logic_findings))
        
        # Risk Assessment
        report_parts.append(PentestReportGenerator._generate_risk_assessment(
            auth_logic_findings,
            username_enum_findings,
            bruteforce_findings,
            mfa_logic_findings,
            token_abuse_findings
        ))
        
        # Detailed Findings
        report_parts.append("\n---\n\n## 📋 Detailed Findings\n")
        
        if username_enum_findings:
            report_parts.append(PentestReportGenerator._generate_username_enum_section(username_enum_findings))
        
        if bruteforce_findings:
            report_parts.append(PentestReportGenerator._generate_bruteforce_section(bruteforce_findings))
        
        if mfa_logic_findings:
            report_parts.append(PentestReportGenerator._generate_mfa_section(mfa_logic_findings))
        
        if token_abuse_findings:
            report_parts.append(PentestReportGenerator._generate_token_abuse_section(token_abuse_findings))
        
        if auth_logic_findings and auth_logic_findings.get("logic_gaps"):
            report_parts.append(PentestReportGenerator._generate_logic_gaps_section(auth_logic_findings))
        
        # Remediation Recommendations
        report_parts.append(PentestReportGenerator._generate_remediation_section(
            auth_logic_findings,
            username_enum_findings,
            bruteforce_findings,
            mfa_logic_findings,
            token_abuse_findings
        ))
        
        # Appendix
        report_parts.append(PentestReportGenerator._generate_appendix(metadata))
        
        return "\n".join(report_parts)
    
    @staticmethod
    def _generate_header(metadata: Dict) -> str:
        """Generate report header with metadata."""
        target = metadata.get("target", "Target Application")
        tester = metadata.get("tester", "Security Analyst")
        date = metadata.get("date", datetime.now().strftime("%Y-%m-%d"))
        version = metadata.get("version", "1.0")
        
        return f"""# Authentication Security Assessment Report

**Target Application:** {target}  
**Assessment Date:** {date}  
**Report Version:** {version}  
**Conducted By:** {tester}  
**Report Classification:** CONFIDENTIAL

---
"""
    
    @staticmethod
    def _generate_executive_summary(
        auth_logic: Optional[Dict],
        username_enum: Optional[Dict],
        bruteforce: Optional[Dict],
        mfa_logic: Optional[Dict],
        token_abuse: Optional[Dict]
    ) -> str:
        """Generate executive summary section."""
        
        # Count vulnerabilities by severity
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        
        all_findings = [auth_logic, username_enum, bruteforce, mfa_logic, token_abuse]
        
        for findings in all_findings:
            if not findings:
                continue
            
            # Count from various finding structures
            if "vulnerabilities" in findings:
                for vuln in findings["vulnerabilities"]:
                    severity = vuln.get("severity", "Medium")
                    if severity == "Critical":
                        critical_count += 1
                    elif severity == "High":
                        high_count += 1
                    elif severity == "Medium":
                        medium_count += 1
                    else:
                        low_count += 1
            
            if "logic_gaps" in findings:
                for gap in findings["logic_gaps"]:
                    severity = gap.get("severity", "Medium")
                    if severity == "Critical":
                        critical_count += 1
                    elif severity == "High":
                        high_count += 1
                    elif severity == "Medium":
                        medium_count += 1
                    else:
                        low_count += 1
            
            if "logic_flaws" in findings:
                for flaw in findings["logic_flaws"]:
                    severity = flaw.get("severity", "Medium")
                    if severity == "Critical":
                        critical_count += 1
                    elif severity == "High":
                        high_count += 1
                    elif severity == "Medium":
                        medium_count += 1
                    else:
                        low_count += 1
        
        total_issues = critical_count + high_count + medium_count + low_count
        
        # Determine overall risk
        if critical_count > 0:
            overall_risk = "**CRITICAL**"
            risk_color = "🔴"
        elif high_count > 0:
            overall_risk = "**HIGH**"
            risk_color = "🟠"
        elif medium_count > 0:
            overall_risk = "**MEDIUM**"
            risk_color = "🟡"
        else:
            overall_risk = "**LOW**"
            risk_color = "🟢"
        
        summary = f"""## 📊 Executive Summary

This report presents the findings from a comprehensive authentication security assessment. The evaluation focused on authentication flow logic, credential handling, multi-factor authentication enforcement, and token security.

### Key Findings

- **Total Issues Identified:** {total_issues}
- **Overall Risk Rating:** {risk_color} {overall_risk}

#### Findings by Severity

| Severity | Count | Description |
|----------|-------|-------------|
| 🔴 Critical | {critical_count} | Immediate remediation required - exploitable vulnerabilities |
| 🟠 High | {high_count} | High priority - significant security risk |
| 🟡 Medium | {medium_count} | Moderate priority - potential security impact |
| 🟢 Low | {low_count} | Low priority - minimal security impact |

"""
        
        # Add key highlights
        highlights = []
        
        if username_enum and username_enum.get("enum_possible"):
            highlights.append("- Username enumeration vulnerability detected")
        
        if mfa_logic and mfa_logic.get("summary", {}).get("bypass_possible"):
            highlights.append("- MFA bypass possible through logic flaws")
        
        if token_abuse and token_abuse.get("pentest_summary", {}).get("critical_count", 0) > 0:
            highlights.append("- Critical JWT/token security vulnerabilities identified")
        
        if bruteforce and bruteforce.get("summary", {}).get("brute_force_viable"):
            highlights.append("- Brute force attacks feasible due to weak defenses")
        
        if highlights:
            summary += "### Critical Highlights\n\n"
            summary += "\n".join(highlights)
            summary += "\n"
        
        return summary
    
    @staticmethod
    def _generate_auth_flow_summary(auth_logic_findings: Dict) -> str:
        """Generate authentication flow summary section."""
        auth_flow = auth_logic_findings.get("authentication_flow", {})
        stages = auth_flow.get("stages", [])
        flow_type = auth_flow.get("flow_type", "Unknown")
        
        section = f"""
---

## 🔐 Authentication Flow Summary

**Authentication Type:** {flow_type}  
**Total Stages:** {auth_flow.get("total_stages", len(stages))}

### Flow Diagram

```
"""
        
        # Create ASCII flow diagram
        for i, stage in enumerate(stages, 1):
            stage_name = stage.get("stage_name", f"Stage {i}")
            endpoint = stage.get("endpoint", "N/A")
            section += f"{i}. {stage_name}\n   └─ Endpoint: {endpoint}\n"
            if i < len(stages):
                section += "   ↓\n"
        
        section += "```\n"
        
        # Add authentication mechanisms
        if "authentication_mechanisms" in auth_logic_findings:
            mechanisms = auth_logic_findings["authentication_mechanisms"]
            section += f"""
### Authentication Mechanisms Identified

- **Primary Method:** {mechanisms.get("primary_method", "Unknown")}
- **Secondary Factors:** {", ".join(mechanisms.get("secondary_factors", [])) or "None"}
- **Token Types:** {", ".join(mechanisms.get("token_types", [])) or "None"}
- **Session Management:** {mechanisms.get("session_management", "Unknown")}
"""
        
        return section
    
    @staticmethod
    def _generate_risk_assessment(
        auth_logic: Optional[Dict],
        username_enum: Optional[Dict],
        bruteforce: Optional[Dict],
        mfa_logic: Optional[Dict],
        token_abuse: Optional[Dict]
    ) -> str:
        """Generate risk assessment section."""
        
        section = """
---

## ⚠️ Risk Assessment

### Attack Surface Analysis

"""
        
        # Authentication Logic Risks
        if auth_logic:
            overall_risk = auth_logic.get("summary", {}).get("overall_risk_rating", "Unknown")
            section += f"**Authentication Logic:** {overall_risk}\n"
        
        # Username Enumeration Risk
        if username_enum:
            risk = username_enum.get("risk_level", "Unknown")
            enum_possible = username_enum.get("enum_possible", False)
            section += f"**Username Enumeration:** {risk} ({'Vulnerable' if enum_possible else 'Not Detected'})\n"
        
        # Brute Force Risk
        if bruteforce:
            risk = bruteforce.get("detection_risk", {}).get("overall_risk", "Unknown")
            viable = bruteforce.get("summary", {}).get("brute_force_viable", False)
            section += f"**Brute Force Feasibility:** {risk} ({'Viable' if viable else 'Not Viable'})\n"
        
        # MFA Risk
        if mfa_logic:
            risk = mfa_logic.get("summary", {}).get("overall_risk", "Unknown")
            bypass = mfa_logic.get("summary", {}).get("bypass_possible", False)
            section += f"**MFA Enforcement:** {risk} ({'Bypassable' if bypass else 'Secure'})\n"
        
        # Token Security Risk
        if token_abuse:
            critical = token_abuse.get("pentest_summary", {}).get("critical_count", 0)
            section += f"**Token Security:** {'Critical' if critical > 0 else 'Acceptable'} ({critical} critical issues)\n"
        
        section += "\n"
        
        return section
    
    @staticmethod
    def _generate_username_enum_section(findings: Dict) -> str:
        """Generate username enumeration findings section."""
        
        enum_possible = findings.get("enum_possible", False)
        confidence = findings.get("confidence_level", "Unknown")
        risk_level = findings.get("risk_level", "Unknown")
        
        section = f"""
### 🔍 Username Enumeration

**Vulnerability Status:** {'VULNERABLE' if enum_possible else 'NOT DETECTED'}  
**Confidence Level:** {confidence}  
**Risk Level:** {risk_level}

"""
        
        evidence = findings.get("evidence", [])
        if evidence:
            section += "#### Evidence\n\n"
            for item in evidence:
                evidence_type = item.get("evidence_type", "Unknown")
                severity = item.get("severity", "Unknown")
                section += f"**{evidence_type}** (Severity: {severity})\n\n"
                
                if "difference_details" in item:
                    details = item["difference_details"]
                    
                    # Error messages
                    if "error_messages" in details:
                        err = details["error_messages"]
                        section += f"- Valid username: `{err.get('valid_username', 'N/A')}`\n"
                        section += f"- Invalid username: `{err.get('invalid_username', 'N/A')}`\n"
                    
                    # Response lengths
                    if "response_lengths" in details:
                        lengths = details["response_lengths"]
                        section += f"- Response length difference: {lengths.get('length_difference', 0)} bytes\n"
                    
                    # Status codes
                    if "status_codes" in details:
                        codes = details["status_codes"]
                        if codes.get("codes_differ"):
                            section += f"- Status codes differ: {codes.get('valid_username')} vs {codes.get('invalid_username')}\n"
                
                section += "\n"
        
        return section
    
    @staticmethod
    def _generate_bruteforce_section(findings: Dict) -> str:
        """Generate brute force feasibility section."""
        
        viable = findings.get("summary", {}).get("brute_force_viable", False)
        recommended_strategy = findings.get("recommended_strategy", "Unknown")
        detection_risk = findings.get("detection_risk", {}).get("overall_risk", "Unknown")
        
        section = f"""
### 🔨 Brute Force Attack Feasibility

**Brute Force Viable:** {'YES' if viable else 'NO'}  
**Recommended Strategy:** {recommended_strategy}  
**Detection Risk:** {detection_risk}

#### Defense Analysis

"""
        
        # Rate limiting
        rate_limit = findings.get("rate_limiting", {})
        section += f"**Rate Limiting:** {'Detected' if rate_limit.get('detected') else 'Not Detected'}\n"
        if rate_limit.get("detected"):
            section += f"- Type: {rate_limit.get('type', 'Unknown')}\n"
            section += f"- Threshold: {rate_limit.get('threshold_estimate', 'Unknown')}\n"
        
        # Account lockout
        lockout = findings.get("account_lockout", {})
        section += f"\n**Account Lockout:** {'Detected' if lockout.get('detected') else 'Not Detected'}\n"
        if lockout.get("detected"):
            section += f"- Threshold: {lockout.get('lockout_threshold', 'Unknown')}\n"
            section += f"- Duration: {lockout.get('lockout_duration', 'Unknown')}\n"
        
        # CAPTCHA
        captcha = findings.get("captcha_protection", {})
        section += f"\n**CAPTCHA:** {'Detected' if captcha.get('detected') else 'Not Detected'}\n"
        if captcha.get("detected"):
            section += f"- Type: {captcha.get('captcha_type', 'Unknown')}\n"
            section += f"- Trigger: {captcha.get('trigger_condition', 'Unknown')}\n"
        
        section += "\n"
        
        return section
    
    @staticmethod
    def _generate_mfa_section(findings: Dict) -> str:
        """Generate MFA logic findings section."""
        
        mfa_type = findings.get("mfa_implementation_type", "Unknown")
        bypass_possible = findings.get("summary", {}).get("bypass_possible", False)
        overall_risk = findings.get("summary", {}).get("overall_risk", "Unknown")
        
        section = f"""
### 🛡️ Multi-Factor Authentication (MFA) Analysis

**MFA Type:** {mfa_type}  
**Bypass Possible:** {'YES - CRITICAL' if bypass_possible else 'NO'}  
**Overall Risk:** {overall_risk}

"""
        
        # Logic flaws
        logic_flaws = findings.get("logic_flaws", [])
        if logic_flaws:
            section += "#### Logic Flaws Identified\n\n"
            for flaw in logic_flaws:
                flaw_type = flaw.get("flaw_type", "Unknown")
                severity = flaw.get("severity", "Unknown")
                description = flaw.get("description", "No description")
                
                section += f"**{flaw_type}** (Severity: {severity})\n\n"
                section += f"{description}\n\n"
                
                if "technical_details" in flaw:
                    details = flaw["technical_details"]
                    section += f"- **Current Behavior:** {details.get('what_happens', 'N/A')}\n"
                    section += f"- **Expected Behavior:** {details.get('what_should_happen', 'N/A')}\n"
                    section += f"- **Logic Gap:** {details.get('logic_gap', 'N/A')}\n\n"
        
        # Endpoint protection
        if "endpoint_protection_analysis" in findings:
            ep_analysis = findings["endpoint_protection_analysis"]
            unprotected = ep_analysis.get("unprotected_endpoints_found", 0)
            
            if unprotected > 0:
                section += f"#### Unprotected Endpoints: {unprotected}\n\n"
                critical_endpoints = ep_analysis.get("critical_endpoints_exposed", [])
                if critical_endpoints:
                    section += "**Critical endpoints accessible without MFA:**\n\n"
                    for endpoint in critical_endpoints:
                        section += f"- `{endpoint}`\n"
                    section += "\n"
        
        return section
    
    @staticmethod
    def _generate_token_abuse_section(findings: Dict) -> str:
        """Generate token abuse findings section."""
        
        token_type = findings.get("token_type", "Unknown")
        total_vulns = findings.get("pentest_summary", {}).get("total_vulnerabilities", 0)
        critical_count = findings.get("pentest_summary", {}).get("critical_count", 0)
        
        section = f"""
### 🎫 Token Security Analysis

**Token Type:** {token_type}  
**Vulnerabilities Found:** {total_vulns}  
**Critical Issues:** {critical_count}

"""
        
        # Vulnerabilities
        vulnerabilities = findings.get("vulnerabilities", [])
        if vulnerabilities:
            section += "#### Vulnerabilities Identified\n\n"
            for vuln in vulnerabilities:
                title = vuln.get("title", "Unknown Vulnerability")
                severity = vuln.get("severity", "Unknown")
                description = vuln.get("description", "No description")
                impact = vuln.get("impact", "Unknown impact")
                
                section += f"**{title}** (Severity: {severity})\n\n"
                section += f"{description}\n\n"
                section += f"**Impact:** {impact}\n\n"
                
                if "exploitation" in vuln:
                    exploit = vuln["exploitation"]
                    difficulty = exploit.get("difficulty", "Unknown")
                    section += f"**Exploitation Difficulty:** {difficulty}\n\n"
        
        # Algorithm analysis
        if "algorithm_analysis" in findings:
            algo = findings["algorithm_analysis"]
            section += f"#### Algorithm Analysis\n\n"
            section += f"- **Algorithm Used:** {algo.get('algorithm_used', 'Unknown')}\n"
            section += f"- **Strength:** {algo.get('algorithm_strength', 'Unknown')}\n\n"
        
        # Claims analysis
        if "claims_analysis" in findings:
            claims = findings["claims_analysis"]
            missing = claims.get("missing_critical_claims", [])
            if missing:
                section += "#### Missing Critical Claims\n\n"
                for claim in missing:
                    section += f"- {claim}\n"
                section += "\n"
        
        return section
    
    @staticmethod
    def _generate_logic_gaps_section(auth_logic_findings: Dict) -> str:
        """Generate authentication logic gaps section."""
        
        logic_gaps = auth_logic_findings.get("logic_gaps", [])
        
        if not logic_gaps:
            return ""
        
        section = """
### 🔓 Authentication Logic Gaps

"""
        
        for gap in logic_gaps:
            gap_type = gap.get("gap_type", "Unknown")
            severity = gap.get("severity", "Unknown")
            description = gap.get("description", "No description")
            potential_impact = gap.get("potential_impact", "Unknown")
            
            section += f"**{gap_type}** (Severity: {severity})\n\n"
            section += f"{description}\n\n"
            section += f"**Potential Impact:** {potential_impact}\n\n"
            
            indicators = gap.get("indicators", [])
            if indicators:
                section += "**Evidence:**\n"
                for indicator in indicators:
                    section += f"- {indicator}\n"
                section += "\n"
        
        return section
    
    @staticmethod
    def _generate_remediation_section(
        auth_logic: Optional[Dict],
        username_enum: Optional[Dict],
        bruteforce: Optional[Dict],
        mfa_logic: Optional[Dict],
        token_abuse: Optional[Dict]
    ) -> str:
        """Generate remediation recommendations section."""
        
        section = """
---

## 🔧 Remediation Recommendations

### Priority Actions

"""
        
        recommendations = []
        
        # Collect all recommendations
        for findings in [auth_logic, username_enum, bruteforce, mfa_logic, token_abuse]:
            if findings and "recommendations" in findings:
                for rec in findings["recommendations"]:
                    recommendations.append(rec)
        
        # Sort by priority
        priority_order = {"Immediate": 0, "High": 1, "Medium": 2, "Low": 3}
        recommendations.sort(key=lambda x: priority_order.get(x.get("priority", "Medium"), 2))
        
        current_priority = None
        for rec in recommendations:
            priority = rec.get("priority", "Medium")
            recommendation_text = rec.get("recommendation", "No recommendation")
            
            # Add priority header if changed
            if priority != current_priority:
                current_priority = priority
                section += f"\n#### {priority} Priority\n\n"
            
            section += f"- **{recommendation_text}**\n"
            
            # Add implementation guidance if available
            if "implementation_guidance" in rec:
                section += f"  - Implementation: {rec['implementation_guidance']}\n"
            elif "implementation" in rec:
                section += f"  - Implementation: {rec['implementation']}\n"
            elif "rationale" in rec:
                section += f"  - Rationale: {rec['rationale']}\n"
            
            section += "\n"
        
        # General best practices
        section += """
### General Security Best Practices

1. **Implement Consistent Error Messages**
   - Return identical error messages for valid and invalid authentication attempts
   - Avoid leaking information about user existence

2. **Enforce Strong Rate Limiting**
   - Implement both IP-based and account-based rate limiting
   - Use progressive delays or exponential backoff

3. **Require Strong Password Policies**
   - Minimum length of 12+ characters
   - Complexity requirements (uppercase, lowercase, numbers, symbols)
   - Check against common password databases

4. **Implement Robust MFA**
   - Enforce MFA at the server level, not client-side
   - Validate MFA completion before issuing access tokens
   - Use time-based OTPs with single-use enforcement

5. **Secure Token Implementation**
   - Always include and validate exp, aud, and iss claims
   - Use strong signature algorithms (RS256 recommended for JWTs)
   - Implement token revocation mechanisms
   - Never accept alg=none

6. **Account Security Controls**
   - Implement account lockout after failed attempts
   - Provide secure account recovery mechanisms
   - Log and monitor authentication events
"""
        
        return section
    
    @staticmethod
    def _generate_appendix(metadata: Dict) -> str:
        """Generate appendix section."""
        
        return f"""
---

## 📚 Appendix

### Methodology

This assessment was conducted using an AI-powered authentication analysis framework that combines multiple specialized agents:

1. **Authentication Logic Agent** - Analyzes authentication flows and state transitions
2. **Username Enumeration Agent** - Detects information disclosure in login responses
3. **Brute Force Strategy Agent** - Assesses feasibility of credential attacks
4. **MFA Logic Agent** - Evaluates multi-factor authentication enforcement
5. **Token Abuse Agent** - Analyzes JWT and session token security

### Risk Rating Definitions

| Rating | Definition |
|--------|------------|
| Critical | Immediate exploitation possible, significant business impact |
| High | Exploitable with moderate effort, serious security impact |
| Medium | Requires specific conditions, moderate security impact |
| Low | Difficult to exploit or minimal security impact |

### References

- OWASP Authentication Cheat Sheet
- OWASP Testing Guide - Authentication Testing
- NIST SP 800-63B - Digital Identity Guidelines
- RFC 7519 - JSON Web Token (JWT)
- CWE-287 - Improper Authentication
- CWE-798 - Use of Hard-coded Credentials

---

**Report Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}  
**Confidentiality Notice:** This document contains sensitive security information and should be handled accordingly.
"""


class ReportGeneratorAgent:
    """
    CrewAI agent wrapper for report generation.
    """
    
    @staticmethod
    def create_agent() -> Agent:
        """
        Creates and configures the Report Generator Agent.
        
        Returns:
            Agent: Configured CrewAI agent
        """
        return Agent(
            role="Security Report Generator",
            
            goal=(
                "Compile findings from all security agents into a comprehensive, "
                "professional penetration testing report suitable for client delivery"
            ),
            
            backstory=(
                "You are a senior security consultant with extensive experience in creating "
                "professional penetration testing reports. You excel at synthesizing technical "
                "findings into clear, actionable recommendations for both technical and executive "
                "audiences. Your reports are known for their clarity, professionalism, and "
                "practical remediation guidance."
            ),
            
            verbose=True,
            allow_delegation=False,
            
            tools=[]
        )
