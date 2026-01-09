"""
Brute Force Feasibility Analysis Agent

A responsible penetration testing agent that analyzes whether brute force attacks
are feasible. Does NOT perform actual brute forcing - only strategic assessment.
"""

from crewai import Agent
from typing import Dict, List


class BruteforceStrategyAgent:
    """
    Responsible penetration testing agent for brute force feasibility analysis.
    
    Analyzes authentication endpoints to determine if brute force attacks are
    feasible, assesses detection risks, and recommends appropriate testing strategies.
    
    IMPORTANT: This agent does NOT perform brute forcing - it only analyzes and advises.
    """
    
    @staticmethod
    def create_agent() -> Agent:
        """
        Creates and configures the Brute Force Strategy Agent.
        
        Returns:
            Agent: Configured CrewAI agent
        """
        return Agent(
            role="Brute Force Feasibility Analyst",
            
            goal=(
                "Analyze authentication endpoints to determine if brute force attacks are feasible "
                "by examining rate limiting, account lockout mechanisms, CAPTCHA implementation, "
                "and password policies. Provide strategic recommendations without performing "
                "actual brute force attacks."
            ),
            
            backstory=(
                "You are a responsible penetration tester with expertise in authentication security "
                "assessments. You understand that brute force testing must be done carefully and "
                "strategically to avoid service disruption and detection. Your role is to analyze "
                "the target's defenses and provide informed recommendations on whether and how "
                "brute force testing should proceed. You assess rate limiting, lockout mechanisms, "
                "CAPTCHA challenges, and password complexity requirements to determine feasibility "
                "and risk. You prioritize responsible disclosure and minimize impact on production "
                "systems."
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
        - rate_limit_detector: Identify rate limiting implementation and thresholds
        - lockout_analyzer: Detect account lockout behavior and policies
        - captcha_detector: Identify CAPTCHA presence, type, and trigger conditions
        - password_policy_parser: Extract password complexity requirements
        - response_pattern_analyzer: Analyze response patterns across multiple requests
        - header_inspector: Check for rate limit headers (X-RateLimit-*, Retry-After)
        
        Returns:
            List[str]: Tool names required by the agent
        """
        return [
            "rate_limit_detector",
            "lockout_analyzer",
            "captcha_detector",
            "password_policy_parser",
            "response_pattern_analyzer",
            "header_inspector"
        ]
    
    @staticmethod
    def get_output_schema() -> Dict:
        """
        Defines the expected JSON output format for feasibility analysis.
        
        Returns:
            Dict: JSON schema for agent output
        """
        return {
            "analysis_id": "string (UUID)",
            "timestamp": "ISO 8601 datetime",
            "endpoint_analyzed": "string (URL)",
            
            "rate_limiting": {
                "detected": "boolean",
                "type": "string (e.g., 'IP-based', 'User-based', 'None detected', 'Token bucket', 'Fixed window')",
                "threshold_estimate": "string (e.g., '5 requests per minute', 'Unknown')",
                "indicators": [
                    "string (evidence of rate limiting)"
                ],
                "bypass_difficulty": "string (Easy/Moderate/Hard/Impossible)",
                "headers_present": {
                    "x_ratelimit_limit": "string or null",
                    "x_ratelimit_remaining": "string or null",
                    "retry_after": "string or null"
                }
            },
            
            "account_lockout": {
                "detected": "boolean",
                "lockout_threshold": "string (e.g., '5 failed attempts', 'Unknown')",
                "lockout_duration": "string (e.g., '30 minutes', 'Permanent', 'Unknown')",
                "indicators": [
                    "string (evidence of lockout mechanism)"
                ],
                "unlocking_mechanism": "string (e.g., 'Time-based', 'Email verification', 'Admin reset', 'Unknown')",
                "severity": "string (Strict/Moderate/Lenient/None)"
            },
            
            "captcha_protection": {
                "detected": "boolean",
                "captcha_type": "string (e.g., 'reCAPTCHA v2', 'reCAPTCHA v3', 'hCaptcha', 'Custom', 'None')",
                "trigger_condition": "string (e.g., 'After 3 failed attempts', 'Always present', 'Random', 'Unknown')",
                "placement": "string (e.g., 'Login page', 'After rate limit', 'Progressive')",
                "bypass_difficulty": "string (Easy/Moderate/Hard/Impossible)"
            },
            
            "password_policy": {
                "detected": "boolean",
                "minimum_length": "int or null",
                "complexity_requirements": [
                    "string (e.g., 'Uppercase required', 'Numbers required', 'Special characters required')"
                ],
                "forbidden_patterns": [
                    "string (e.g., 'Common passwords blocked', 'Username in password blocked')"
                ],
                "policy_source": "string (e.g., 'Registration page', 'Error message', 'Password reset', 'Inferred')",
                "strength_meter": "boolean (whether strength indicator is present)"
            },
            
            "recommended_strategy": "string (e.g., 'Not Feasible - Strong Defenses', 'Targeted Attack - Specific Accounts', 'Low-and-Slow Approach', 'Credential Stuffing Viable', 'Dictionary Attack Possible')",
            
            "detection_risk": {
                "overall_risk": "string (Critical/High/Medium/Low)",
                "risk_factors": [
                    {
                        "factor": "string (e.g., 'No rate limiting', 'WAF present', 'Logging detected')",
                        "impact": "string (Increases/Decreases detection risk)"
                    }
                ],
                "stealth_requirements": [
                    "string (recommendations for avoiding detection)"
                ]
            },
            
            "reasoning": {
                "feasibility_assessment": "string (detailed explanation of whether brute force is feasible)",
                "key_findings": [
                    "string (important observations)"
                ],
                "defense_strengths": [
                    "string (effective protections identified)"
                ],
                "defense_weaknesses": [
                    "string (gaps in protection)"
                ],
                "alternative_approaches": [
                    "string (other attack vectors to consider)"
                ]
            },
            
            "recommendations": [
                {
                    "category": "string (e.g., 'Testing Approach', 'Risk Mitigation', 'Alternative Vectors')",
                    "recommendation": "string",
                    "justification": "string"
                }
            ],
            
            "responsible_testing_notes": {
                "max_safe_request_rate": "string (e.g., '1 request per 5 seconds')",
                "test_account_recommended": "boolean",
                "production_impact_risk": "string (High/Medium/Low)",
                "client_notification_required": "boolean",
                "warnings": [
                    "string (important cautions)"
                ]
            },
            
            "summary": {
                "brute_force_viable": "boolean",
                "recommended_action": "string (Proceed with caution/Not recommended/Modify approach/Use alternative method)",
                "primary_obstacle": "string (main defense preventing brute force)",
                "estimated_success_rate": "string (High/Medium/Low/Very Low)"
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
            "Analyze authentication endpoint defenses to assess brute force feasibility:\n\n"
            "1. RATE LIMITING ANALYSIS:\n"
            "   - Check for rate limiting headers (X-RateLimit-*, Retry-After)\n"
            "   - Identify rate limit thresholds from responses\n"
            "   - Determine if rate limiting is IP-based, user-based, or both\n"
            "   - Assess bypass difficulty\n\n"
            "2. ACCOUNT LOCKOUT DETECTION:\n"
            "   - Identify lockout behavior from error messages\n"
            "   - Estimate lockout threshold (e.g., 5 failed attempts)\n"
            "   - Determine lockout duration (temporary vs permanent)\n"
            "   - Identify unlocking mechanisms\n\n"
            "3. CAPTCHA ANALYSIS:\n"
            "   - Detect CAPTCHA presence and type (reCAPTCHA, hCaptcha, etc.)\n"
            "   - Identify trigger conditions (always, after N attempts, etc.)\n"
            "   - Assess bypass difficulty\n"
            "   - Note progressive CAPTCHA implementation\n\n"
            "4. PASSWORD POLICY INFERENCE:\n"
            "   - Extract password requirements from registration/reset pages\n"
            "   - Identify complexity requirements from error messages\n"
            "   - Note forbidden patterns (common passwords, usernames)\n"
            "   - Assess impact on brute force dictionary\n\n"
            "5. STRATEGIC ASSESSMENT:\n"
            "   - Determine if brute force is feasible\n"
            "   - Calculate detection risk\n"
            "   - Recommend testing strategy (or advise against testing)\n"
            "   - Suggest alternative attack vectors if brute force is not viable\n"
            "   - Provide responsible testing guidelines\n\n"
            "DO NOT perform actual brute forcing - only analyze and recommend.\n"
            "Output findings in structured JSON format with clear reasoning."
        )
    
    @staticmethod
    def get_strategy_examples() -> Dict:
        """
        Provides example scenarios and recommended strategies.
        
        Returns:
            Dict: Example strategies for different defense configurations
        """
        return {
            "scenarios": [
                {
                    "name": "Strong Defenses - Not Feasible",
                    "defenses": {
                        "rate_limiting": "5 requests/minute, IP-based",
                        "account_lockout": "3 attempts, 1 hour lockout",
                        "captcha": "reCAPTCHA v3 after 2 attempts"
                    },
                    "recommended_strategy": "Not Feasible - Strong Defenses",
                    "detection_risk": "Critical",
                    "reasoning": "Multiple overlapping defenses make brute force impractical"
                },
                {
                    "name": "Weak Defenses - Low and Slow Viable",
                    "defenses": {
                        "rate_limiting": "100 requests/minute",
                        "account_lockout": "None detected",
                        "captcha": "None"
                    },
                    "recommended_strategy": "Low-and-Slow Approach",
                    "detection_risk": "Medium",
                    "reasoning": "Lenient rate limits allow careful testing, no lockout risk"
                },
                {
                    "name": "No Defenses - High Risk Detection",
                    "defenses": {
                        "rate_limiting": "None",
                        "account_lockout": "None",
                        "captcha": "None"
                    },
                    "recommended_strategy": "Targeted Attack - Specific Accounts",
                    "detection_risk": "High",
                    "reasoning": "Lack of defenses suggests monitoring/logging instead"
                },
                {
                    "name": "CAPTCHA Only - Credential Stuffing",
                    "defenses": {
                        "rate_limiting": "None",
                        "account_lockout": "None",
                        "captcha": "reCAPTCHA after 5 attempts"
                    },
                    "recommended_strategy": "Credential Stuffing Viable",
                    "detection_risk": "Low",
                    "reasoning": "Single attempt per account stays under CAPTCHA threshold"
                }
            ]
        }
