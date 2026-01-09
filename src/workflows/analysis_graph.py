"""
LangGraph Orchestration - Attack Decision Engine

Defines the state graph for coordinating agent execution in authentication testing:
1. AuthLogicAgent (analyze flow)
2. Conditional routing based on findings
3. UsernameEnumAgent → BruteforceStrategyAgent → MFALogicAgent → TokenAbuseAgent
4. Aggregate findings into final report

Handles:
- State management across agents
- Conditional routing (skip agents when not applicable)
- Sequential execution with decision logic
- Final report aggregation
"""

from typing import TypedDict, List, Dict, Optional, Literal
from langgraph.graph import StateGraph, END
from datetime import datetime
import json


# ============================================================================
# STATE SCHEMA
# ============================================================================

class AuthAnalysisState(TypedDict):
    """
    Shared state that flows through the entire analysis workflow.
    Each agent reads from and writes to this state.
    """
    # Input data
    raw_requests: List[str]  # Raw HTTP requests from Burp
    raw_responses: List[str]  # Raw HTTP responses from Burp
    analysis_context: Dict  # Additional context (target URL, scope, etc.)
    
    # Parsed data
    parsed_requests: List[Dict]  # Parsed HTTP request structures
    parsed_responses: List[Dict]  # Parsed HTTP response structures
    
    # Agent execution tracking
    agents_executed: List[str]  # Track which agents have run
    agents_skipped: List[str]  # Track which agents were skipped
    skip_reasons: Dict[str, str]  # Why each agent was skipped
    
    # Agent findings
    auth_logic_findings: Optional[Dict]  # From AuthLogicAgent
    username_enum_findings: Optional[Dict]  # From UsernameEnumAgent
    bruteforce_strategy_findings: Optional[Dict]  # From BruteforceStrategyAgent
    mfa_logic_findings: Optional[Dict]  # From MFALogicAgent
    token_abuse_findings: Optional[Dict]  # From TokenAbuseAgent
    
    # Decision flags (control flow)
    has_login_endpoint: bool  # Whether login functionality detected
    has_multiple_responses: bool  # Multiple responses for comparison
    has_mfa_implementation: bool  # Whether MFA is present
    has_tokens: bool  # Whether JWT/session tokens detected
    bruteforce_viable: bool  # Whether bruteforce testing is feasible
    
    # Aggregated results
    final_report: Optional[Dict]  # Complete analysis report
    
    # Error tracking
    errors: List[Dict]  # Any errors encountered during execution


# ============================================================================
# AGENT NODE FUNCTIONS
# ============================================================================

def auth_logic_analysis_node(state: AuthAnalysisState) -> AuthAnalysisState:
    """
    Entry node: Analyze authentication flow with AuthLogicAgent.
    
    Sets decision flags for downstream agents:
    - has_login_endpoint
    - has_mfa_implementation
    - has_tokens
    """
    print("🔍 Running AuthLogicAgent...")
    
    # TODO: Actual agent execution (placeholder for now)
    # This would call AuthLogicAgent.create_agent() and execute task
    
    # Simulate analysis
    auth_findings = {
        "analysis_id": f"auth-{datetime.now().isoformat()}",
        "authentication_flow": {
            "stages": [
                {"stage_name": "Initial Login", "endpoint": "/api/login"},
                {"stage_name": "Token Generation", "endpoint": "/api/auth/token"},
                {"stage_name": "MFA Challenge", "endpoint": "/api/mfa/challenge"},
            ],
            "flow_type": "JWT with MFA"
        },
        "logic_gaps": [],
        "summary": {
            "total_gaps_found": 0,
            "overall_risk_rating": "Medium"
        }
    }
    
    # Update state
    state["auth_logic_findings"] = auth_findings
    state["agents_executed"].append("AuthLogicAgent")
    
    # Set decision flags based on findings
    state["has_login_endpoint"] = True  # Detected login endpoint
    state["has_mfa_implementation"] = "MFA" in auth_findings["authentication_flow"]["flow_type"]
    state["has_tokens"] = "JWT" in auth_findings["authentication_flow"]["flow_type"]
    
    return state


def username_enum_analysis_node(state: AuthAnalysisState) -> AuthAnalysisState:
    """
    Analyze login responses for username enumeration vulnerabilities.
    Requires multiple responses for comparison.
    """
    print("🔍 Running UsernameEnumAgent...")
    
    # TODO: Actual agent execution
    
    # Simulate analysis
    enum_findings = {
        "analysis_id": f"enum-{datetime.now().isoformat()}",
        "enum_possible": True,
        "confidence_level": "High",
        "evidence": [
            {
                "evidence_type": "Error Message Difference",
                "severity": "High"
            }
        ],
        "risk_level": "High"
    }
    
    state["username_enum_findings"] = enum_findings
    state["agents_executed"].append("UsernameEnumAgent")
    
    return state


def bruteforce_strategy_analysis_node(state: AuthAnalysisState) -> AuthAnalysisState:
    """
    Analyze feasibility of brute force attacks.
    Sets bruteforce_viable flag for decision making.
    """
    print("🔍 Running BruteforceStrategyAgent...")
    
    # TODO: Actual agent execution
    
    # Simulate analysis
    bruteforce_findings = {
        "analysis_id": f"bf-{datetime.now().isoformat()}",
        "rate_limiting": {"detected": False},
        "account_lockout": {"detected": False},
        "captcha_protection": {"detected": False},
        "recommended_strategy": "Low-and-Slow Approach",
        "detection_risk": {"overall_risk": "Medium"},
        "summary": {"brute_force_viable": True}
    }
    
    state["bruteforce_strategy_findings"] = bruteforce_findings
    state["agents_executed"].append("BruteforceStrategyAgent")
    state["bruteforce_viable"] = bruteforce_findings["summary"]["brute_force_viable"]
    
    return state


def mfa_logic_analysis_node(state: AuthAnalysisState) -> AuthAnalysisState:
    """
    Analyze MFA enforcement logic for flaws.
    Only runs if MFA is detected in auth flow.
    """
    print("🔍 Running MFALogicAgent...")
    
    # TODO: Actual agent execution
    
    # Simulate analysis
    mfa_findings = {
        "analysis_id": f"mfa-{datetime.now().isoformat()}",
        "mfa_implementation_type": "TOTP",
        "logic_flaws": [
            {
                "flaw_type": "MFA Bypass After Token Issuance",
                "severity": "Critical"
            }
        ],
        "summary": {
            "bypass_possible": True,
            "overall_risk": "Critical"
        }
    }
    
    state["mfa_logic_findings"] = mfa_findings
    state["agents_executed"].append("MFALogicAgent")
    
    return state


def token_abuse_analysis_node(state: AuthAnalysisState) -> AuthAnalysisState:
    """
    Analyze JWT/session tokens for security vulnerabilities.
    Only runs if tokens are detected in auth flow.
    """
    print("🔍 Running TokenAbuseAgent...")
    
    # TODO: Actual agent execution
    
    # Simulate analysis
    token_findings = {
        "analysis_id": f"token-{datetime.now().isoformat()}",
        "token_type": "JWT",
        "vulnerabilities": [
            {
                "title": "Missing Expiration Claim",
                "severity": "High"
            }
        ],
        "pentest_summary": {
            "total_vulnerabilities": 3,
            "critical_count": 1
        }
    }
    
    state["token_abuse_findings"] = token_findings
    state["agents_executed"].append("TokenAbuseAgent")
    
    return state


def aggregate_report_node(state: AuthAnalysisState) -> AuthAnalysisState:
    """
    Final node: Aggregate all findings into comprehensive report.
    """
    print("📊 Aggregating final report...")
    
    # Collect all findings
    all_findings = {}
    
    if state.get("auth_logic_findings"):
        all_findings["authentication_logic"] = state["auth_logic_findings"]
    
    if state.get("username_enum_findings"):
        all_findings["username_enumeration"] = state["username_enum_findings"]
    
    if state.get("bruteforce_strategy_findings"):
        all_findings["bruteforce_feasibility"] = state["bruteforce_strategy_findings"]
    
    if state.get("mfa_logic_findings"):
        all_findings["mfa_enforcement"] = state["mfa_logic_findings"]
    
    if state.get("token_abuse_findings"):
        all_findings["token_security"] = state["token_abuse_findings"]
    
    # Create comprehensive report
    final_report = {
        "report_id": f"report-{datetime.now().isoformat()}",
        "generated_at": datetime.now().isoformat(),
        "analysis_summary": {
            "total_agents_executed": len(state["agents_executed"]),
            "agents_executed": state["agents_executed"],
            "agents_skipped": state["agents_skipped"],
            "skip_reasons": state["skip_reasons"]
        },
        "findings_by_category": all_findings,
        "risk_assessment": {
            "overall_risk": calculate_overall_risk(all_findings),
            "critical_findings": extract_critical_findings(all_findings),
            "high_findings": extract_high_findings(all_findings)
        },
        "recommendations": aggregate_recommendations(all_findings),
        "executive_summary": generate_executive_summary(all_findings, state)
    }
    
    state["final_report"] = final_report
    
    return state


# ============================================================================
# CONDITIONAL ROUTING LOGIC
# ============================================================================

def should_run_username_enum(state: AuthAnalysisState) -> Literal["username_enum", "bruteforce_strategy", "skip_all"]:
    """
    Decide if UsernameEnumAgent should run.
    
    Requires:
    - Login endpoint detected
    - Multiple responses available for comparison
    """
    if not state.get("has_login_endpoint", False):
        state["agents_skipped"].append("UsernameEnumAgent")
        state["skip_reasons"]["UsernameEnumAgent"] = "No login endpoint detected"
        return "bruteforce_strategy"
    
    if not state.get("has_multiple_responses", False):
        state["agents_skipped"].append("UsernameEnumAgent")
        state["skip_reasons"]["UsernameEnumAgent"] = "Insufficient response samples for comparison"
        return "bruteforce_strategy"
    
    return "username_enum"


def should_run_bruteforce(state: AuthAnalysisState) -> Literal["bruteforce_strategy", "mfa_logic", "skip_to_mfa"]:
    """
    Decide if BruteforceStrategyAgent should run.
    
    Requires:
    - Login endpoint detected
    """
    if not state.get("has_login_endpoint", False):
        state["agents_skipped"].append("BruteforceStrategyAgent")
        state["skip_reasons"]["BruteforceStrategyAgent"] = "No login endpoint detected"
        return "mfa_logic"
    
    return "bruteforce_strategy"


def should_run_mfa(state: AuthAnalysisState) -> Literal["mfa_logic", "token_abuse", "skip_to_token"]:
    """
    Decide if MFALogicAgent should run.
    
    Requires:
    - MFA implementation detected in auth flow
    """
    if not state.get("has_mfa_implementation", False):
        state["agents_skipped"].append("MFALogicAgent")
        state["skip_reasons"]["MFALogicAgent"] = "No MFA implementation detected"
        return "token_abuse"
    
    return "mfa_logic"


def should_run_token_abuse(state: AuthAnalysisState) -> Literal["token_abuse", "aggregate", "skip_to_aggregate"]:
    """
    Decide if TokenAbuseAgent should run.
    
    Requires:
    - JWT or session tokens detected
    """
    if not state.get("has_tokens", False):
        state["agents_skipped"].append("TokenAbuseAgent")
        state["skip_reasons"]["TokenAbuseAgent"] = "No tokens detected in authentication flow"
        return "aggregate"
    
    return "token_abuse"


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def calculate_overall_risk(findings: Dict) -> str:
    """Calculate overall risk level from all findings."""
    critical_count = 0
    high_count = 0
    
    for category, data in findings.items():
        if isinstance(data, dict):
            # Check for critical/high severity findings
            if "vulnerabilities" in data:
                for vuln in data["vulnerabilities"]:
                    if vuln.get("severity") == "Critical":
                        critical_count += 1
                    elif vuln.get("severity") == "High":
                        high_count += 1
    
    if critical_count > 0:
        return "Critical"
    elif high_count > 0:
        return "High"
    else:
        return "Medium"


def extract_critical_findings(findings: Dict) -> List[str]:
    """Extract all critical severity findings."""
    critical = []
    for category, data in findings.items():
        if isinstance(data, dict) and "vulnerabilities" in data:
            for vuln in data["vulnerabilities"]:
                if vuln.get("severity") == "Critical":
                    critical.append(f"{category}: {vuln.get('title', 'Unknown')}")
    return critical


def extract_high_findings(findings: Dict) -> List[str]:
    """Extract all high severity findings."""
    high = []
    for category, data in findings.items():
        if isinstance(data, dict) and "vulnerabilities" in data:
            for vuln in data["vulnerabilities"]:
                if vuln.get("severity") == "High":
                    high.append(f"{category}: {vuln.get('title', 'Unknown')}")
    return high


def aggregate_recommendations(findings: Dict) -> List[Dict]:
    """Aggregate recommendations from all agent findings."""
    recommendations = []
    for category, data in findings.items():
        if isinstance(data, dict) and "recommendations" in data:
            for rec in data["recommendations"]:
                recommendations.append({
                    "category": category,
                    **rec
                })
    return recommendations


def generate_executive_summary(findings: Dict, state: AuthAnalysisState) -> str:
    """Generate executive summary for the report."""
    summary_parts = []
    
    summary_parts.append(
        f"Authentication security analysis completed with {len(state['agents_executed'])} "
        f"specialized agents. "
    )
    
    critical_count = len(extract_critical_findings(findings))
    high_count = len(extract_high_findings(findings))
    
    if critical_count > 0:
        summary_parts.append(
            f"CRITICAL: {critical_count} critical vulnerability(ies) identified requiring immediate attention. "
        )
    
    if high_count > 0:
        summary_parts.append(
            f"{high_count} high-severity finding(s) detected. "
        )
    
    return "".join(summary_parts)


# ============================================================================
# GRAPH CONSTRUCTION
# ============================================================================

def create_auth_analysis_graph() -> StateGraph:
    """
    Create the LangGraph workflow for authentication analysis.
    
    Flow:
    1. START → AuthLogicAgent (always runs)
    2. AuthLogicAgent → UsernameEnumAgent (conditional)
    3. UsernameEnumAgent → BruteforceStrategyAgent (conditional)
    4. BruteforceStrategyAgent → MFALogicAgent (conditional)
    5. MFALogicAgent → TokenAbuseAgent (conditional)
    6. TokenAbuseAgent → AggregateReport (always)
    7. AggregateReport → END
    
    Returns:
        StateGraph: Configured LangGraph workflow
    """
    # Initialize graph
    workflow = StateGraph(AuthAnalysisState)
    
    # Add nodes
    workflow.add_node("auth_logic", auth_logic_analysis_node)
    workflow.add_node("username_enum", username_enum_analysis_node)
    workflow.add_node("bruteforce_strategy", bruteforce_strategy_analysis_node)
    workflow.add_node("mfa_logic", mfa_logic_analysis_node)
    workflow.add_node("token_abuse", token_abuse_analysis_node)
    workflow.add_node("aggregate", aggregate_report_node)
    
    # Set entry point
    workflow.set_entry_point("auth_logic")
    
    # Add conditional edges
    workflow.add_conditional_edges(
        "auth_logic",
        should_run_username_enum,
        {
            "username_enum": "username_enum",
            "bruteforce_strategy": "bruteforce_strategy",
            "skip_all": "aggregate"
        }
    )
    
    workflow.add_conditional_edges(
        "username_enum",
        should_run_bruteforce,
        {
            "bruteforce_strategy": "bruteforce_strategy",
            "mfa_logic": "mfa_logic",
            "skip_to_mfa": "mfa_logic"
        }
    )
    
    workflow.add_conditional_edges(
        "bruteforce_strategy",
        should_run_mfa,
        {
            "mfa_logic": "mfa_logic",
            "token_abuse": "token_abuse",
            "skip_to_token": "token_abuse"
        }
    )
    
    workflow.add_conditional_edges(
        "mfa_logic",
        should_run_token_abuse,
        {
            "token_abuse": "token_abuse",
            "aggregate": "aggregate",
            "skip_to_aggregate": "aggregate"
        }
    )
    
    workflow.add_conditional_edges(
        "token_abuse",
        lambda state: "aggregate",
        {
            "aggregate": "aggregate"
        }
    )
    
    # Final edge to END
    workflow.add_edge("aggregate", END)
    
    return workflow


def initialize_state(
    raw_requests: List[str],
    raw_responses: List[str],
    context: Optional[Dict] = None
) -> AuthAnalysisState:
    """
    Initialize the workflow state with input data.
    
    Args:
        raw_requests: List of raw HTTP requests
        raw_responses: List of raw HTTP responses
        context: Additional context (target URL, scope, etc.)
    
    Returns:
        AuthAnalysisState: Initialized state
    """
    return {
        "raw_requests": raw_requests,
        "raw_responses": raw_responses,
        "analysis_context": context or {},
        "parsed_requests": [],
        "parsed_responses": [],
        "agents_executed": [],
        "agents_skipped": [],
        "skip_reasons": {},
        "auth_logic_findings": None,
        "username_enum_findings": None,
        "bruteforce_strategy_findings": None,
        "mfa_logic_findings": None,
        "token_abuse_findings": None,
        "has_login_endpoint": False,
        "has_multiple_responses": len(raw_responses) > 1,
        "has_mfa_implementation": False,
        "has_tokens": False,
        "bruteforce_viable": False,
        "final_report": None,
        "errors": []
    }


# ============================================================================
# USAGE EXAMPLE
# ============================================================================

def run_analysis(raw_requests: List[str], raw_responses: List[str]) -> Dict:
    """
    Execute the complete authentication analysis workflow.
    
    Args:
        raw_requests: List of raw HTTP requests from Burp
        raw_responses: List of raw HTTP responses from Burp
    
    Returns:
        Dict: Final analysis report
    """
    # Create graph
    graph = create_auth_analysis_graph()
    app = graph.compile()
    
    # Initialize state
    initial_state = initialize_state(raw_requests, raw_responses)
    
    # Execute workflow
    final_state = app.invoke(initial_state)
    
    # Return final report
    return final_state.get("final_report", {})
