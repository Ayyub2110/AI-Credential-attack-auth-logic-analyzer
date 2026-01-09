"""
JWT and Token Security Analysis Agent

A specialized CrewAI agent for analyzing JWT and session tokens for common
security vulnerabilities and abuse scenarios.
"""

from crewai import Agent
from typing import Dict, List


class TokenAbuseAgent:
    """
    JWT security specialist agent for token vulnerability analysis.
    
    Analyzes decoded JWTs and session tokens to identify security weaknesses
    including algorithm attacks, missing claims, and privilege escalation risks.
    """
    
    @staticmethod
    def create_agent() -> Agent:
        """
        Creates and configures the Token Abuse Analysis Agent.
        
        Returns:
            Agent: Configured CrewAI agent
        """
        return Agent(
            role="JWT and Token Security Specialist",
            
            goal=(
                "Analyze JWT tokens and session tokens to identify security vulnerabilities "
                "including algorithm bypass (alg=none), key confusion (HS256/RS256), missing "
                "critical claims (exp, aud, iss), token reuse after logout, and privilege "
                "escalation opportunities in token-based authentication systems"
            ),
            
            backstory=(
                "You are a JWT security expert with deep knowledge of token-based authentication "
                "vulnerabilities. You've analyzed thousands of JWT implementations and understand "
                "the subtle flaws that lead to authentication bypass and privilege escalation. "
                "You're familiar with common JWT attacks including algorithm confusion, none algorithm "
                "bypass, claim manipulation, and token reuse. Your expertise helps identify weaknesses "
                "in token validation, signature verification, and claim enforcement. You provide "
                "clear, actionable findings that penetration testers can use to demonstrate risk "
                "and help developers fix token security issues."
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
        - jwt_decoder: Decode JWT tokens and extract header/payload
        - algorithm_analyzer: Analyze JWT algorithm and signature strength
        - claim_validator: Check for required claims and validate values
        - signature_verifier: Analyze signature verification implementation
        - token_comparator: Compare tokens across different states (before/after logout, different users)
        - privilege_analyzer: Analyze role/permission claims for escalation vectors
        
        Returns:
            List[str]: Tool names required by the agent
        """
        return [
            "jwt_decoder",
            "algorithm_analyzer",
            "claim_validator",
            "signature_verifier",
            "token_comparator",
            "privilege_analyzer"
        ]
    
    @staticmethod
    def get_output_schema() -> Dict:
        """
        Defines the expected JSON output format for token analysis.
        Pentest-friendly format with clear findings and exploitation notes.
        
        Returns:
            Dict: JSON schema for agent output
        """
        return {
            "analysis_id": "string (UUID)",
            "timestamp": "ISO 8601 datetime",
            "token_type": "string (JWT/Session Token/API Key/Bearer Token)",
            
            "token_details": {
                "header": "dict (decoded JWT header)",
                "payload": "dict (decoded JWT payload/claims)",
                "signature_present": "boolean",
                "encoding": "string (e.g., 'Base64URL', 'Hex')"
            },
            
            "vulnerabilities": [
                {
                    "vuln_id": "string (e.g., 'JWT-001')",
                    "title": "string (e.g., 'Algorithm None Attack Possible')",
                    "severity": "string (Critical/High/Medium/Low)",
                    "category": "string (e.g., 'Algorithm Bypass', 'Missing Claims', 'Privilege Escalation')",
                    "description": "string (detailed explanation)",
                    "evidence": {
                        "finding": "string (what was found)",
                        "location": "string (header/payload/signature)",
                        "value": "string (actual value found)"
                    },
                    "exploitation": {
                        "difficulty": "string (Easy/Moderate/Hard)",
                        "steps": [
                            "string (step-by-step exploitation guidance)"
                        ],
                        "payload_example": "string (example manipulated token)",
                        "tools_required": [
                            "string (tools needed for exploitation)"
                        ]
                    },
                    "impact": "string (what attacker can achieve)",
                    "remediation": "string (how to fix)",
                    "references": [
                        "string (CVE, OWASP, research papers)"
                    ]
                }
            ],
            
            "algorithm_analysis": {
                "algorithm_used": "string (e.g., 'HS256', 'RS256', 'none')",
                "algorithm_strength": "string (Strong/Weak/None)",
                "vulnerabilities_found": [
                    {
                        "type": "string (e.g., 'alg=none Accepted', 'HS256/RS256 Confusion Possible')",
                        "risk": "string (Critical/High/Medium/Low)",
                        "details": "string (explanation)",
                        "test_vector": "string (how to test this)"
                    }
                ],
                "signature_verification": {
                    "appears_validated": "boolean",
                    "weak_secret_suspected": "boolean",
                    "public_key_exposed": "boolean"
                }
            },
            
            "claims_analysis": {
                "required_claims_present": {
                    "exp": {
                        "present": "boolean",
                        "value": "string or null",
                        "valid": "boolean",
                        "issue": "string or null (e.g., 'Token never expires', 'Expiration too long')"
                    },
                    "aud": {
                        "present": "boolean",
                        "value": "string or null",
                        "valid": "boolean",
                        "issue": "string or null (e.g., 'Missing audience validation')"
                    },
                    "iss": {
                        "present": "boolean",
                        "value": "string or null",
                        "valid": "boolean",
                        "issue": "string or null (e.g., 'Missing issuer validation')"
                    },
                    "iat": {
                        "present": "boolean",
                        "value": "string or null"
                    },
                    "nbf": {
                        "present": "boolean",
                        "value": "string or null"
                    }
                },
                "custom_claims": [
                    {
                        "claim_name": "string",
                        "claim_value": "string",
                        "security_relevant": "boolean",
                        "manipulation_risk": "string (High/Medium/Low)"
                    }
                ],
                "missing_critical_claims": [
                    "string (claim name and why it's important)"
                ]
            },
            
            "token_reuse_analysis": {
                "tested": "boolean",
                "reuse_after_logout_possible": "boolean or null",
                "evidence": "string (how this was determined)",
                "invalidation_mechanism": "string (None/Server-side blacklist/Token rotation/Unknown)",
                "risk": "string (Critical/High/Medium/Low)"
            },
            
            "privilege_escalation": {
                "role_claims_found": [
                    {
                        "claim_name": "string (e.g., 'role', 'permissions', 'admin')",
                        "current_value": "string",
                        "modifiable": "boolean",
                        "escalation_vector": "string (how to escalate)",
                        "target_value": "string (value to escalate to)"
                    }
                ],
                "privilege_escalation_possible": "boolean",
                "severity": "string (Critical/High/Medium/Low)",
                "attack_scenario": "string (detailed escalation scenario)"
            },
            
            "additional_findings": [
                {
                    "finding": "string",
                    "severity": "string (Critical/High/Medium/Low)",
                    "details": "string"
                }
            ],
            
            "pentest_summary": {
                "executive_summary": "string (brief overview for reports)",
                "total_vulnerabilities": "int",
                "critical_count": "int",
                "high_count": "int",
                "exploitability_rating": "string (Easy/Moderate/Difficult)",
                "recommended_tests": [
                    "string (specific tests to perform)"
                ],
                "proof_of_concept_required": "boolean"
            },
            
            "recommendations": [
                {
                    "priority": "string (Immediate/High/Medium/Low)",
                    "recommendation": "string",
                    "implementation_guide": "string (how to implement)"
                }
            ]
        }
    
    @staticmethod
    def get_task_description() -> str:
        """
        Returns the task description for the agent.
        
        Returns:
            str: Task description
        """
        return (
            "Analyze JWT and session tokens for security vulnerabilities:\n\n"
            "1. ALGORITHM ANALYSIS:\n"
            "   - Check for 'alg=none' bypass vulnerability\n"
            "   - Detect HS256/RS256 algorithm confusion potential\n"
            "   - Identify weak or missing signature verification\n"
            "   - Test for algorithm substitution attacks\n"
            "   - Assess signature strength and key management\n\n"
            "2. CLAIMS VALIDATION:\n"
            "   - Verify presence of 'exp' (expiration) claim\n"
            "   - Check for 'aud' (audience) claim and validation\n"
            "   - Verify 'iss' (issuer) claim is present\n"
            "   - Analyze 'iat' (issued at) and 'nbf' (not before)\n"
            "   - Identify missing or improperly validated claims\n"
            "   - Check expiration times (too long = risk)\n\n"
            "3. TOKEN REUSE ANALYSIS:\n"
            "   - Determine if tokens remain valid after logout\n"
            "   - Check for server-side token invalidation\n"
            "   - Identify token rotation mechanisms\n"
            "   - Test for blacklisting/revocation capabilities\n"
            "   - Assess session management security\n\n"
            "4. PRIVILEGE ESCALATION:\n"
            "   - Identify role/permission claims (role, admin, permissions)\n"
            "   - Check if claims can be manipulated\n"
            "   - Test for missing signature verification on modified tokens\n"
            "   - Map escalation paths (user → admin)\n"
            "   - Assess impact of claim modification\n\n"
            "5. ADDITIONAL SECURITY CHECKS:\n"
            "   - Weak secret detection (common keys, short secrets)\n"
            "   - Public key exposure\n"
            "   - Token structure analysis\n"
            "   - Sensitive data in payload\n"
            "   - JTI (JWT ID) for replay prevention\n\n"
            "Provide pentest-friendly output with clear exploitation steps and PoC guidance.\n"
            "Focus on practical vulnerabilities that can be demonstrated."
        )
    
    @staticmethod
    def get_vulnerability_examples() -> Dict:
        """
        Provides example JWT vulnerabilities for reference.
        
        Returns:
            Dict: Examples of common JWT vulnerabilities
        """
        return {
            "alg_none_attack": {
                "description": "JWT accepts 'none' algorithm, bypassing signature verification",
                "original_header": {"alg": "HS256", "typ": "JWT"},
                "attack_header": {"alg": "none", "typ": "JWT"},
                "payload": {"sub": "user123", "role": "admin"},
                "attack_token": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6ImFkbWluIn0.",
                "severity": "Critical"
            },
            "hs256_rs256_confusion": {
                "description": "Server accepts HS256 when expecting RS256, using public key as HMAC secret",
                "attack_steps": [
                    "Obtain server's public RSA key",
                    "Use public key as HMAC secret with HS256",
                    "Sign modified payload with HS256",
                    "Server validates with public key as HMAC secret"
                ],
                "severity": "Critical"
            },
            "missing_exp": {
                "description": "Token lacks expiration claim, remains valid indefinitely",
                "vulnerable_payload": {"sub": "user123", "role": "user"},
                "secure_payload": {"sub": "user123", "role": "user", "exp": 1735344000},
                "severity": "High"
            },
            "privilege_escalation": {
                "description": "Role claim can be modified without proper signature verification",
                "original_payload": {"sub": "user123", "role": "user"},
                "attack_payload": {"sub": "user123", "role": "admin"},
                "severity": "Critical"
            },
            "token_reuse": {
                "description": "Token remains valid after logout (no server-side invalidation)",
                "test": "Logout, then reuse token - if accepted, vulnerability confirmed",
                "severity": "High"
            }
        }
