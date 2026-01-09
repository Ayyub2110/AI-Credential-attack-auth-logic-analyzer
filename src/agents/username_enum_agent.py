"""
Username Enumeration Detection Agent

A specialized CrewAI agent for detecting username enumeration vulnerabilities
by comparing login responses for valid and invalid usernames.
"""

from crewai import Agent
from typing import Dict, List


class UsernameEnumAgent:
    """
    Offensive security agent specialized in detecting username enumeration vulnerabilities.
    
    Analyzes multiple login responses to identify information disclosure that could
    allow attackers to enumerate valid usernames.
    """
    
    @staticmethod
    def create_agent() -> Agent:
        """
        Creates and configures the Username Enumeration Detection Agent.
        
        Returns:
            Agent: Configured CrewAI agent
        """
        return Agent(
            role="Username Enumeration Security Analyst",
            
            goal=(
                "Compare multiple login responses to detect username enumeration vulnerabilities "
                "by identifying differences in error messages, response lengths, status codes, "
                "and timing patterns that leak information about valid vs invalid usernames"
            ),
            
            backstory=(
                "You are an offensive security specialist with deep expertise in authentication "
                "bypass techniques. You excel at identifying subtle differences in application "
                "responses that reveal whether a username exists in the system. You understand "
                "that even minor variations in error messages, response sizes, HTTP status codes, "
                "or processing logic can be exploited to enumerate valid accounts, enabling "
                "targeted attacks. Your analysis helps organizations prevent information disclosure "
                "that aids attackers in reconnaissance."
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
        - response_comparator: Compare multiple HTTP responses for differences
        - error_analyzer: Analyze error message patterns and variations
        - length_calculator: Calculate and compare response body lengths
        - status_analyzer: Analyze HTTP status code patterns
        - timing_pattern_detector: Identify logical timing indicators (not measurements)
        - header_comparator: Compare response headers for differences
        
        Returns:
            List[str]: Tool names required by the agent
        """
        return [
            "response_comparator",
            "error_analyzer",
            "length_calculator",
            "status_analyzer",
            "timing_pattern_detector",
            "header_comparator"
        ]
    
    @staticmethod
    def get_output_schema() -> Dict:
        """
        Defines the expected JSON output format for enumeration analysis.
        
        Returns:
            Dict: JSON schema for agent output
        """
        return {
            "analysis_id": "string (UUID)",
            "timestamp": "ISO 8601 datetime",
            "enum_possible": "boolean (true if username enumeration is possible)",
            "confidence_level": "string (High/Medium/Low)",
            "evidence": [
                {
                    "evidence_type": "string (e.g., 'Error Message Difference', 'Response Length Variation', 'Status Code Difference', 'Timing Pattern')",
                    "description": "string (detailed explanation of the finding)",
                    "valid_username_behavior": "string (what happens with valid username)",
                    "invalid_username_behavior": "string (what happens with invalid username)",
                    "difference_details": {
                        "error_messages": {
                            "valid_username": "string (error message shown for valid username)",
                            "invalid_username": "string (error message shown for invalid username)",
                            "similarity_score": "float (0.0-1.0, how similar the messages are)"
                        },
                        "response_lengths": {
                            "valid_username": "int (bytes)",
                            "invalid_username": "int (bytes)",
                            "length_difference": "int (bytes)"
                        },
                        "status_codes": {
                            "valid_username": "int (HTTP status code)",
                            "invalid_username": "int (HTTP status code)",
                            "codes_differ": "boolean"
                        },
                        "timing_indicators": {
                            "valid_username_pattern": "string (e.g., 'Database lookup performed', 'Password hash comparison')",
                            "invalid_username_pattern": "string (e.g., 'Early return', 'No database query')",
                            "logical_difference": "string (description of processing difference)"
                        }
                    },
                    "severity": "string (Critical/High/Medium/Low)"
                }
            ],
            "risk_level": "string (Critical/High/Medium/Low)",
            "attack_scenarios": [
                {
                    "scenario": "string (how enumeration can be exploited)",
                    "impact": "string (potential damage)"
                }
            ],
            "recommendations": [
                {
                    "priority": "string (High/Medium/Low)",
                    "fix": "string (remediation action)",
                    "implementation": "string (how to implement the fix)"
                }
            ],
            "samples_analyzed": {
                "total_requests": "int",
                "valid_username_samples": "int",
                "invalid_username_samples": "int"
            },
            "summary": {
                "enumeration_vectors": "int (number of ways enumeration is possible)",
                "primary_vector": "string (most obvious enumeration method)",
                "exploitability": "string (Easy/Moderate/Difficult)",
                "remediation_urgency": "string (Immediate/High/Medium/Low)"
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
            "Analyze login responses to detect username enumeration vulnerabilities:\n\n"
            "1. ERROR MESSAGE ANALYSIS:\n"
            "   - Compare error messages for valid vs invalid usernames\n"
            "   - Identify revealing differences (e.g., 'Invalid password' vs 'User not found')\n"
            "   - Check for subtle wording variations\n"
            "   - Analyze error codes or identifiers\n\n"
            "2. RESPONSE LENGTH COMPARISON:\n"
            "   - Calculate response body sizes\n"
            "   - Identify consistent length differences\n"
            "   - Check for patterns across multiple samples\n"
            "   - Consider dynamic content impact\n\n"
            "3. STATUS CODE ANALYSIS:\n"
            "   - Compare HTTP status codes\n"
            "   - Identify different codes for valid/invalid usernames\n"
            "   - Check for non-standard status usage\n\n"
            "4. TIMING PATTERN DETECTION (LOGICAL):\n"
            "   - Identify logical processing differences\n"
            "   - Detect database lookup vs early return patterns\n"
            "   - Analyze password hashing indicators for valid users\n"
            "   - Note computational complexity differences\n"
            "   - DO NOT perform actual timing measurements\n\n"
            "5. HEADER COMPARISON:\n"
            "   - Compare response headers\n"
            "   - Check for different headers (Set-Cookie, etc.)\n"
            "   - Identify header value variations\n\n"
            "Output findings in structured JSON format with clear evidence and risk assessment.\n"
            "Focus on DETECTION, not exploitation."
        )
    
    @staticmethod
    def get_detection_examples() -> Dict:
        """
        Provides example patterns of username enumeration vulnerabilities.
        
        Returns:
            Dict: Examples of enumeration patterns
        """
        return {
            "error_message_patterns": {
                "vulnerable": {
                    "valid_username": "Invalid password for user 'admin'",
                    "invalid_username": "User 'nonexistent' not found"
                },
                "secure": {
                    "both": "Invalid username or password"
                }
            },
            "response_length_patterns": {
                "vulnerable": {
                    "valid_username": 1247,
                    "invalid_username": 1189,
                    "difference": 58
                },
                "secure": {
                    "both": "Should be identical or randomized"
                }
            },
            "status_code_patterns": {
                "vulnerable": {
                    "valid_username": 401,  # Unauthorized (wrong password)
                    "invalid_username": 404  # Not Found (user doesn't exist)
                },
                "secure": {
                    "both": 401  # Same code for both cases
                }
            },
            "timing_logic_patterns": {
                "vulnerable": {
                    "valid_username": "Database query + bcrypt hash comparison (slow)",
                    "invalid_username": "Early return without database query (fast)"
                },
                "secure": {
                    "both": "Constant-time comparison with dummy operations"
                }
            }
        }
