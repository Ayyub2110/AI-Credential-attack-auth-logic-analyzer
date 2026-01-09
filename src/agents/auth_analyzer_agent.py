"""
Authentication Logic Analyzer Agent

A specialized CrewAI agent for analyzing authentication flows and detecting logic vulnerabilities.
"""

from crewai import Agent
from typing import Dict, List


class AuthLogicAgent:
    """
    Penetration testing agent specialized in authentication logic analysis.
    
    Analyzes HTTP request/response pairs to identify authentication flow stages
    and detect logic gaps that could lead to authentication bypass.
    """
    
    @staticmethod
    def create_agent() -> Agent:
        """
        Creates and configures the Authentication Logic Agent.
        
        Returns:
            Agent: Configured CrewAI agent
        """
        return Agent(
            role="Authentication Logic Security Analyst",
            
            goal=(
                "Analyze HTTP request/response pairs to map complete authentication flows, "
                "identify all authentication stages (login, token generation, MFA, session creation, access control), "
                "and detect logic gaps or vulnerabilities that could allow authentication bypass"
            ),
            
            backstory=(
                "You are an expert penetration tester specializing in authentication mechanisms. "
                "With years of experience in breaking authentication systems, you understand common "
                "implementation flaws, state transition vulnerabilities, and logic gaps in multi-stage "
                "authentication flows. You meticulously trace request/response patterns to identify "
                "weaknesses in login sequences, token handling, MFA implementation, and session management."
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
        - http_parser: Extract headers, cookies, parameters from HTTP requests/responses
        - token_analyzer: Decode and analyze JWT, session tokens, OAuth tokens
        - flow_mapper: Track authentication state transitions across multiple requests
        - pattern_matcher: Identify authentication patterns (login, MFA, token refresh)
        - logic_checker: Detect missing validation, state confusion, race conditions
        - header_analyzer: Analyze security headers (Authorization, Set-Cookie, CORS)
        - parameter_tracker: Track parameter flow across authentication stages
        
        Returns:
            List[str]: Tool names required by the agent
        """
        return [
            "http_parser",
            "token_analyzer", 
            "flow_mapper",
            "pattern_matcher",
            "logic_checker",
            "header_analyzer",
            "parameter_tracker"
        ]
    
    @staticmethod
    def get_output_schema() -> Dict:
        """
        Defines the expected JSON output format for analysis results.
        
        Returns:
            Dict: JSON schema for agent output
        """
        return {
            "analysis_id": "string (UUID)",
            "timestamp": "ISO 8601 datetime",
            "authentication_flow": {
                "stages": [
                    {
                        "stage_number": "int",
                        "stage_name": "string (e.g., 'Initial Login', 'Token Generation', 'MFA Challenge', 'MFA Verification', 'Session Creation', 'Protected Resource Access')",
                        "request_method": "string (GET/POST/etc.)",
                        "endpoint": "string (URL path)",
                        "authentication_data": {
                            "credentials_sent": "boolean",
                            "tokens_received": "list of token types",
                            "cookies_set": "list of cookie names",
                            "headers_required": "list of header names"
                        },
                        "state_transition": "string (description of state change)"
                    }
                ],
                "total_stages": "int",
                "flow_type": "string (e.g., 'Basic Auth', 'JWT', 'OAuth 2.0', 'Session-based', 'MFA-enabled')"
            },
            "logic_gaps": [
                {
                    "gap_id": "string",
                    "severity": "string (Critical/High/Medium/Low)",
                    "gap_type": "string (e.g., 'Missing State Validation', 'Token Not Verified', 'MFA Bypass Possible', 'Race Condition')",
                    "description": "string (detailed explanation)",
                    "affected_stages": "list of stage numbers",
                    "indicators": [
                        "string (specific evidence from requests/responses)"
                    ],
                    "potential_impact": "string (what could be exploited)"
                }
            ],
            "authentication_mechanisms": {
                "primary_method": "string",
                "secondary_factors": "list of strings",
                "token_types": "list of strings",
                "session_management": "string"
            },
            "security_observations": [
                {
                    "category": "string (e.g., 'Token Security', 'Session Management', 'Input Validation')",
                    "observation": "string",
                    "risk_level": "string"
                }
            ],
            "recommendations": [
                {
                    "priority": "string (High/Medium/Low)",
                    "recommendation": "string (what should be fixed)",
                    "rationale": "string (why it matters)"
                }
            ],
            "summary": {
                "total_gaps_found": "int",
                "critical_issues": "int",
                "flow_completeness": "string (Complete/Incomplete/Broken)",
                "overall_risk_rating": "string (Critical/High/Medium/Low)"
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
            "Analyze the provided HTTP request/response pairs to:\n"
            "1. Map the complete authentication flow from initial login to resource access\n"
            "2. Identify all authentication stages (login → token generation → MFA → session → access)\n"
            "3. Detect logic gaps such as:\n"
            "   - Missing state validation between stages\n"
            "   - Token verification bypasses\n"
            "   - MFA enforcement gaps\n"
            "   - Session fixation opportunities\n"
            "   - Race conditions in state transitions\n"
            "   - Authorization checks not enforced\n"
            "4. Document all findings in structured JSON format\n"
            "5. Provide actionable security recommendations\n\n"
            "Focus on LOGIC vulnerabilities, not implementation bugs or exploits."
        )
