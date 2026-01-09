"""
MFA Enforcement Logic Analysis Agent

A specialized CrewAI agent for analyzing Multi-Factor Authentication (MFA)
implementation logic and identifying enforcement gaps and bypass opportunities.
"""

from crewai import Agent
from typing import Dict, List


class MFALogicAgent:
    """
    MFA security specialist agent for analyzing authentication flow logic.
    
    Detects logic flaws in MFA implementation including enforcement gaps,
    client-side only validation, OTP reuse, and endpoint protection issues.
    
    IMPORTANT: Focuses on logic analysis, NOT bypass payload generation.
    """
    
    @staticmethod
    def create_agent() -> Agent:
        """
        Creates and configures the MFA Logic Analysis Agent.
        
        Returns:
            Agent: Configured CrewAI agent
        """
        return Agent(
            role="MFA Enforcement Logic Analyst",
            
            goal=(
                "Analyze Multi-Factor Authentication implementation to detect logic flaws "
                "including MFA bypass after token issuance, client-side only enforcement, "
                "reusable OTP vulnerabilities, and direct access to post-MFA endpoints. "
                "Identify enforcement gaps without generating exploit payloads."
            ),
            
            backstory=(
                "You are an authentication security expert specializing in MFA implementation "
                "analysis. You've reviewed countless MFA systems and understand the subtle logic "
                "flaws that allow attackers to bypass multi-factor authentication. You know that "
                "MFA is often implemented incorrectly - enforced on the client instead of server, "
                "skippable after initial token issuance, or not protecting all critical endpoints. "
                "You excel at tracing authentication flows to identify exactly where MFA validation "
                "is missing or improperly enforced. Your role is to document logic gaps clearly so "
                "developers can understand and fix the architectural flaws."
            ),
            
            verbose=True,
            allow_delegation=False,
            
            # Tools will be injected during runtime
            tools=[]
        )
    
    @staticmethod
    def get_required_tools() -> List[str]:
        """
        Lists the tools required by this agent.
        
        Tools:
        - flow_analyzer: Trace authentication flow from login through MFA to resource access
        - endpoint_mapper: Map all authentication-related endpoints and their protection
        - token_tracker: Track token states before and after MFA
        - otp_validator: Analyze OTP generation and validation logic
        - client_server_detector: Identify client-side vs server-side enforcement
        - state_transition_checker: Verify proper state management in auth flows
        
        Returns:
            List[str]: Tool names required by the agent
        """
        return [
            "flow_analyzer",
            "endpoint_mapper",
            "token_tracker",
            "otp_validator",
            "client_server_detector",
            "state_transition_checker"
        ]
    
    @staticmethod
    def get_output_schema() -> Dict:
        """
        Defines the expected JSON output format for MFA logic analysis.
        
        Returns:
            Dict: JSON schema for agent output
        """
        return {
            "analysis_id": "string (UUID)",
            "timestamp": "ISO 8601 datetime",
            "mfa_implementation_type": "string (e.g., 'TOTP', 'SMS OTP', 'Email OTP', 'Push Notification', 'Hardware Token')",
            
            "authentication_flow": {
                "stages": [
                    {
                        "stage_number": "int",
                        "stage_name": "string (e.g., 'Initial Login', 'Token Issuance', 'MFA Challenge', 'MFA Verification', 'Resource Access')",
                        "endpoint": "string",
                        "mfa_required": "boolean",
                        "mfa_enforced": "string (Server-side/Client-side/Not Enforced/Unknown)"
                    }
                ],
                "flow_type": "string (e.g., 'Login → Token → MFA → Access', 'Login → MFA → Token → Access')"
            },
            
            "logic_flaws": [
                {
                    "flaw_id": "string (e.g., 'MFA-001')",
                    "flaw_type": "string (e.g., 'MFA Bypass After Token Issuance', 'Client-Side Only Enforcement', 'Reusable OTP', 'Unprotected Post-MFA Endpoint')",
                    "severity": "string (Critical/High/Medium/Low)",
                    "description": "string (detailed explanation of the logic flaw)",
                    "flow_stage_affected": "int or list of ints",
                    "technical_details": {
                        "what_happens": "string (current behavior)",
                        "what_should_happen": "string (secure behavior)",
                        "logic_gap": "string (specific gap in enforcement)"
                    },
                    "evidence": [
                        "string (observations that indicate this flaw)"
                    ],
                    "attack_scenario": "string (how attacker exploits this - NO payloads)",
                    "impact": "string (what attacker achieves)",
                    "remediation": "string (how to fix the logic flaw)"
                }
            ],
            
            "mfa_skip_after_token": {
                "vulnerable": "boolean",
                "details": {
                    "token_issued_before_mfa": "boolean",
                    "token_valid_without_mfa": "boolean",
                    "flow_description": "string (explain the flow)",
                    "logic_gap": "string (why MFA can be skipped)",
                    "proof_of_flaw": "string (evidence, NO exploit code)"
                },
                "severity": "string (Critical/High/Medium/Low)"
            },
            
            "client_side_enforcement": {
                "detected": "boolean",
                "details": {
                    "enforcement_location": "string (Client-side/Server-side/Both/Mixed)",
                    "server_validation_present": "boolean",
                    "client_validation_only": "boolean",
                    "indicators": [
                        "string (evidence of client-side only enforcement)"
                    ],
                    "bypass_logic": "string (explain how client enforcement can be bypassed - NO code)",
                    "affected_endpoints": [
                        "string (endpoints with weak enforcement)"
                    ]
                },
                "severity": "string (Critical/High/Medium/Low)"
            },
            
            "otp_reuse_analysis": {
                "reuse_possible": "boolean",
                "details": {
                    "otp_invalidated_after_use": "boolean",
                    "single_use_enforced": "boolean",
                    "time_window": "string (OTP validity period)",
                    "test_observations": "string (what was observed during testing)",
                    "logic_flaw_explanation": "string (why reuse is possible)",
                    "rate_limiting_on_otp": "boolean"
                },
                "severity": "string (Critical/High/Medium/Low)"
            },
            
            "endpoint_protection_analysis": {
                "post_mfa_endpoints_identified": [
                    {
                        "endpoint": "string (URL/path)",
                        "purpose": "string (what this endpoint does)",
                        "mfa_required": "boolean",
                        "mfa_enforced": "boolean",
                        "accessible_without_mfa": "boolean",
                        "protection_mechanism": "string (e.g., 'Token check only', 'MFA state verified', 'No protection')",
                        "vulnerability": "string or null (if accessible without MFA)"
                    }
                ],
                "unprotected_endpoints_found": "int",
                "critical_endpoints_exposed": [
                    "string (critical endpoints accessible without MFA)"
                ]
            },
            
            "state_management_issues": {
                "issues_found": [
                    {
                        "issue": "string (e.g., 'MFA state not tracked server-side', 'State can be manipulated', 'Race condition in MFA verification')",
                        "description": "string",
                        "impact": "string",
                        "severity": "string (Critical/High/Medium/Low)"
                    }
                ]
            },
            
            "additional_findings": [
                {
                    "category": "string (e.g., 'OTP Generation', 'Session Management', 'Token Validation')",
                    "finding": "string",
                    "security_impact": "string",
                    "severity": "string (Critical/High/Medium/Low)"
                }
            ],
            
            "summary": {
                "mfa_enforcement_strength": "string (Weak/Moderate/Strong)",
                "critical_flaws_count": "int",
                "bypass_possible": "boolean",
                "primary_weakness": "string (main logic flaw)",
                "overall_risk": "string (Critical/High/Medium/Low)"
            },
            
            "recommendations": [
                {
                    "priority": "string (Immediate/High/Medium/Low)",
                    "recommendation": "string",
                    "rationale": "string (why this is important)",
                    "implementation_guidance": "string (how to implement)"
                }
            ],
            
            "compliance_notes": {
                "pci_dss_compliance": "string (Compliant/Non-compliant/Partial)",
                "nist_compliance": "string (Compliant/Non-compliant/Partial)",
                "issues": [
                    "string (compliance issues identified)"
                ]
            }
        }
    
    @staticmethod
    def get_task_description() -> str:
        """
        Returns the task description for the agent.
        
        Returns:
            str: Task description
        """
        return (
            "Analyze Multi-Factor Authentication enforcement logic for flaws:\n\n"
            "1. MFA BYPASS AFTER TOKEN ISSUANCE:\n"
            "   - Trace authentication flow: Login → Token → MFA → Access\n"
            "   - Check if token is issued BEFORE MFA completion\n"
            "   - Verify if pre-MFA token grants access to resources\n"
            "   - Identify if MFA can be skipped after obtaining initial token\n"
            "   - Document the flow gap that allows bypass\n\n"
            "2. CLIENT-SIDE ONLY ENFORCEMENT:\n"
            "   - Determine if MFA is enforced on server or client\n"
            "   - Look for JavaScript-based MFA checks\n"
            "   - Verify server validates MFA completion\n"
            "   - Check if MFA prompts can be bypassed by direct API calls\n"
            "   - Identify endpoints that skip server-side MFA verification\n\n"
            "3. REUSABLE OTP DETECTION:\n"
            "   - Check if OTP is invalidated after successful use\n"
            "   - Verify single-use enforcement\n"
            "   - Test if same OTP works multiple times\n"
            "   - Check OTP validity window (too long = risk)\n"
            "   - Identify lack of rate limiting on OTP attempts\n\n"
            "4. DIRECT ACCESS TO POST-MFA ENDPOINTS:\n"
            "   - Map all endpoints accessed after MFA\n"
            "   - Test if post-MFA endpoints require MFA validation\n"
            "   - Check if endpoints only verify token, not MFA state\n"
            "   - Identify critical endpoints accessible without MFA\n"
            "   - Document endpoint protection gaps\n\n"
            "5. STATE MANAGEMENT ANALYSIS:\n"
            "   - Verify server tracks MFA completion state\n"
            "   - Check for race conditions in MFA verification\n"
            "   - Identify state manipulation opportunities\n"
            "   - Analyze session handling post-MFA\n\n"
            "DO NOT generate bypass payloads or exploit code.\n"
            "Focus on explaining LOGIC FLAWS in clear, architectural terms.\n"
            "Provide implementation guidance for remediation."
        )
    
    @staticmethod
    def get_logic_flaw_examples() -> Dict:
        """
        Provides example MFA logic flaws for reference.
        
        Returns:
            Dict: Examples of common MFA logic flaws
        """
        return {
            "token_before_mfa": {
                "flaw": "Token issued before MFA completion",
                "vulnerable_flow": "Login (credentials) → Access Token Issued → MFA Challenge → MFA Verify → Access Granted",
                "secure_flow": "Login (credentials) → MFA Challenge → MFA Verify → Access Token Issued → Access Granted",
                "logic_gap": "Access token is valid even if user never completes MFA",
                "impact": "User can authenticate with credentials only, bypassing MFA entirely",
                "severity": "Critical"
            },
            "client_side_mfa": {
                "flaw": "MFA enforced only in client-side JavaScript",
                "vulnerable_behavior": "JavaScript redirects to MFA page, but API endpoints don't verify MFA completion",
                "secure_behavior": "Server checks MFA completion state before allowing access to protected resources",
                "logic_gap": "Direct API calls bypass client-side MFA prompt",
                "impact": "Attacker can skip MFA by calling APIs directly",
                "severity": "Critical"
            },
            "reusable_otp": {
                "flaw": "OTP not invalidated after successful use",
                "vulnerable_behavior": "Same OTP code works multiple times within validity window",
                "secure_behavior": "OTP invalidated immediately after first successful use",
                "logic_gap": "No single-use enforcement on server side",
                "impact": "Stolen OTP can be used multiple times, extended attack window",
                "severity": "High"
            },
            "unprotected_endpoints": {
                "flaw": "Post-MFA endpoints accessible with pre-MFA token",
                "vulnerable_endpoints": [
                    "/api/user/profile (checks token only)",
                    "/api/transactions (checks token only)",
                    "/api/sensitive-data (checks token only)"
                ],
                "secure_endpoints": [
                    "/api/user/profile (checks token + MFA state)",
                    "/api/transactions (checks token + MFA state)",
                    "/api/sensitive-data (checks token + MFA state)"
                ],
                "logic_gap": "Endpoints verify token validity but not MFA completion",
                "impact": "All supposedly MFA-protected resources accessible without MFA",
                "severity": "Critical"
            },
            "state_not_tracked": {
                "flaw": "MFA completion state not tracked server-side",
                "vulnerable_behavior": "Server doesn't maintain MFA verification status in session",
                "secure_behavior": "Server tracks MFA completion and validates on every sensitive request",
                "logic_gap": "No server-side state management for MFA status",
                "impact": "Cannot enforce MFA requirement consistently",
                "severity": "Critical"
            }
        }
