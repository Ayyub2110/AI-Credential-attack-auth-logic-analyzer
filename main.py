"""
Main entry point for the AI-powered authentication logic analyzer.

Usage:
    python main.py --input <burp_file_or_directory>
    python main.py --demo  # Run with demo data
    python main.py --request request.txt --response response.txt
"""

import argparse
import sys
import os
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.tools.burp_parser import HTTPParser
from src.workflows.analysis_graph import (
    create_auth_analysis_graph,
    initialize_state,
    AuthAnalysisState
)
from src.agents.report_generator_agent import PentestReportGenerator
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn


console = Console()


def load_sample_data() -> tuple[List[str], List[str]]:
    """
    Load sample HTTP request/response data for demonstration.
    
    Returns:
        tuple: (raw_requests, raw_responses)
    """
    # Sample login request - invalid username
    sample_request_1 = """POST /api/auth/login HTTP/1.1
Host: target-app.com
Content-Type: application/json
User-Agent: Mozilla/5.0
Content-Length: 52

{"username":"invaliduser","password":"testpass123"}"""

    # Sample login response - invalid username
    sample_response_1 = """HTTP/1.1 404 Not Found
Content-Type: application/json
Content-Length: 45

{"error":"User not found","success":false}"""

    # Sample login request - valid username, wrong password
    sample_request_2 = """POST /api/auth/login HTTP/1.1
Host: target-app.com
Content-Type: application/json
User-Agent: Mozilla/5.0
Content-Length: 48

{"username":"admin","password":"wrongpassword"}"""

    # Sample login response - valid username
    sample_response_2 = """HTTP/1.1 401 Unauthorized
Content-Type: application/json
Content-Length: 58

{"error":"Invalid password for user admin","success":false}"""

    # Sample successful login request
    sample_request_3 = """POST /api/auth/login HTTP/1.1
Host: target-app.com
Content-Type: application/json
User-Agent: Mozilla/5.0
Content-Length: 48

{"username":"admin","password":"correctpassword"}"""

    # Sample successful login response with token
    sample_response_3 = """HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: session=abc123xyz; HttpOnly; Secure
Content-Length: 156

{"success":true,"token":"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJ1c2VyIn0.","user_id":1,"requires_mfa":true}"""

    # MFA challenge request
    sample_request_4 = """GET /api/mfa/challenge HTTP/1.1
Host: target-app.com
Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJ1c2VyIn0.
Cookie: session=abc123xyz"""

    # MFA challenge response
    sample_response_4 = """HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 78

{"success":true,"challenge_id":"ch-12345","method":"totp","message":"Enter OTP"}"""

    # Protected resource access without MFA
    sample_request_5 = """GET /api/user/profile HTTP/1.1
Host: target-app.com
Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJ1c2VyIn0.
Cookie: session=abc123xyz"""

    # Protected resource response (vulnerable - no MFA check)
    sample_response_5 = """HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 98

{"user_id":1,"username":"admin","email":"admin@example.com","role":"user","mfa_enabled":true}"""

    return (
        [sample_request_1, sample_request_2, sample_request_3, sample_request_4, sample_request_5],
        [sample_response_1, sample_response_2, sample_response_3, sample_response_4, sample_response_5]
    )


def load_from_file(filepath: str) -> str:
    """
    Load raw HTTP data from file.
    
    Args:
        filepath: Path to file containing HTTP request or response
    
    Returns:
        str: Raw HTTP content
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        console.print(f"[red]Error reading file {filepath}: {e}[/red]")
        sys.exit(1)


def load_from_directory(dirpath: str) -> tuple[List[str], List[str]]:
    """
    Load all HTTP request/response files from directory.
    
    Args:
        dirpath: Path to directory containing HTTP files
    
    Returns:
        tuple: (raw_requests, raw_responses)
    """
    requests = []
    responses = []
    
    dir_path = Path(dirpath)
    
    # Look for request files
    for req_file in sorted(dir_path.glob("*request*.txt")):
        requests.append(load_from_file(str(req_file)))
    
    # Look for response files
    for resp_file in sorted(dir_path.glob("*response*.txt")):
        responses.append(load_from_file(str(resp_file)))
    
    return requests, responses


def parse_http_data(raw_requests: List[str], raw_responses: List[str]) -> AuthAnalysisState:
    """
    Parse raw HTTP data using HTTPParser.
    
    Args:
        raw_requests: List of raw HTTP requests
        raw_responses: List of raw HTTP responses
    
    Returns:
        AuthAnalysisState: Initialized state with parsed data
    """
    console.print("\n[cyan]📝 Parsing HTTP data...[/cyan]")
    
    parsed_requests = []
    parsed_responses = []
    
    # Parse requests
    for i, raw_req in enumerate(raw_requests, 1):
        parsed = HTTPParser.parse_request(raw_req)
        if parsed.get("error_message"):
            console.print(f"[yellow]Warning: Request {i} parse error: {parsed['error_message']}[/yellow]")
        else:
            console.print(f"[green]✓[/green] Parsed request {i}: {parsed.get('method')} {parsed.get('endpoint')}")
        parsed_requests.append(parsed)
    
    # Parse responses
    for i, raw_resp in enumerate(raw_responses, 1):
        parsed = HTTPParser.parse_response(raw_resp)
        if parsed.get("error_message"):
            console.print(f"[yellow]Warning: Response {i} parse error: {parsed['error_message']}[/yellow]")
        else:
            console.print(f"[green]✓[/green] Parsed response {i}: {parsed.get('status_code')} ({parsed.get('response_length')} bytes)")
        parsed_responses.append(parsed)
    
    # Initialize state
    state = initialize_state(raw_requests, raw_responses)
    state["parsed_requests"] = parsed_requests
    state["parsed_responses"] = parsed_responses
    
    return state


def run_analysis(state: AuthAnalysisState) -> Dict:
    """
    Execute the LangGraph workflow to analyze authentication.
    
    Args:
        state: Initialized analysis state
    
    Returns:
        Dict: Final state after workflow execution
    """
    console.print("\n[cyan]🔬 Starting authentication analysis workflow...[/cyan]\n")
    
    # Create and compile graph
    graph = create_auth_analysis_graph()
    app = graph.compile()
    
    # Execute workflow with progress display
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Analyzing authentication flow...", total=None)
            
            # Run the workflow
            final_state = app.invoke(state)
            
            progress.update(task, description="[green]✓ Analysis complete")
        
        return final_state
    
    except Exception as e:
        console.print(f"\n[red]Error during analysis: {e}[/red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def generate_report(final_state: Dict, output_path: Optional[str] = None) -> str:
    """
    Generate the final penetration testing report.
    
    Args:
        final_state: Final state from workflow execution
        output_path: Optional path to save report (defaults to reports/report_<timestamp>.md)
    
    Returns:
        str: Path to generated report
    """
    console.print("\n[cyan]📊 Generating penetration testing report...[/cyan]")
    
    # Prepare metadata
    metadata = {
        "target": final_state.get("analysis_context", {}).get("target", "Target Application"),
        "tester": "AI-Powered Authentication Analyzer",
        "date": datetime.now().strftime("%Y-%m-%d"),
        "version": "1.0"
    }
    
    # Generate report
    report_markdown = PentestReportGenerator.generate_markdown_report(
        auth_logic_findings=final_state.get("auth_logic_findings"),
        username_enum_findings=final_state.get("username_enum_findings"),
        bruteforce_findings=final_state.get("bruteforce_strategy_findings"),
        mfa_logic_findings=final_state.get("mfa_logic_findings"),
        token_abuse_findings=final_state.get("token_abuse_findings"),
        metadata=metadata
    )
    
    # Determine output path
    if not output_path:
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = reports_dir / f"pentest_report_{timestamp}.md"
    
    # Save report
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report_markdown)
        console.print(f"[green]✓ Report saved to: {output_path}[/green]")
        return str(output_path)
    except Exception as e:
        console.print(f"[red]Error saving report: {e}[/red]")
        sys.exit(1)


def display_summary(final_state: Dict):
    """
    Display analysis summary to console.
    
    Args:
        final_state: Final state from workflow execution
    """
    console.print("\n" + "="*70)
    console.print(Panel.fit(
        "[bold cyan]Analysis Summary[/bold cyan]",
        border_style="cyan"
    ))
    
    # Agents executed
    agents_executed = final_state.get("agents_executed", [])
    agents_skipped = final_state.get("agents_skipped", [])
    
    console.print(f"\n[bold]Agents Executed:[/bold] {len(agents_executed)}")
    for agent in agents_executed:
        console.print(f"  [green]✓[/green] {agent}")
    
    if agents_skipped:
        console.print(f"\n[bold]Agents Skipped:[/bold] {len(agents_skipped)}")
        skip_reasons = final_state.get("skip_reasons", {})
        for agent in agents_skipped:
            reason = skip_reasons.get(agent, "Unknown reason")
            console.print(f"  [yellow]⊘[/yellow] {agent}: {reason}")
    
    # Quick findings summary
    console.print("\n[bold]Quick Findings:[/bold]")
    
    findings_count = 0
    
    # Username enumeration
    username_enum = final_state.get("username_enum_findings") or {}
    if username_enum.get("enum_possible"):
        console.print("  [red]⚠[/red] Username enumeration vulnerability detected")
        findings_count += 1
    
    # Brute force
    bruteforce = final_state.get("bruteforce_strategy_findings") or {}
    if bruteforce.get("summary", {}).get("brute_force_viable"):
        console.print("  [yellow]⚠[/yellow] Brute force attacks are viable")
        findings_count += 1
    
    # MFA bypass
    mfa = final_state.get("mfa_logic_findings") or {}
    if mfa.get("summary", {}).get("bypass_possible"):
        console.print("  [red]⚠[/red] MFA bypass possible")
        findings_count += 1
    
    # Token vulnerabilities
    token = final_state.get("token_abuse_findings") or {}
    token_critical = token.get("pentest_summary", {}).get("critical_count", 0)
    if token_critical > 0:
        console.print(f"  [red]⚠[/red] {token_critical} critical token vulnerabilities found")
        findings_count += 1
    
    if findings_count == 0:
        console.print("  [green]✓[/green] No major vulnerabilities detected")
    
    console.print("\n" + "="*70 + "\n")


def main():
    """Main entry point for the authentication analyzer."""
    
    # ASCII banner
    console.print("""
[cyan]
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   AI-Powered Authentication Logic Analyzer                       ║
║   CrewAI + LangGraph Security Assessment Framework               ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
[/cyan]
""")
    
    # Parse arguments
    parser = argparse.ArgumentParser(
        description="AI-powered authentication security analyzer"
    )
    parser.add_argument(
        '--demo',
        action='store_true',
        help='Run with demo data'
    )
    parser.add_argument(
        '--input',
        type=str,
        help='Path to Burp request file or directory containing HTTP files'
    )
    parser.add_argument(
        '--request',
        type=str,
        help='Path to single HTTP request file'
    )
    parser.add_argument(
        '--response',
        type=str,
        help='Path to single HTTP response file'
    )
    parser.add_argument(
        '--output',
        type=str,
        help='Output path for report (default: reports/report_<timestamp>.md)'
    )
    parser.add_argument(
        '--target',
        type=str,
        default='Target Application',
        help='Target application name for report'
    )
    
    args = parser.parse_args()
    
    # Load data
    raw_requests = []
    raw_responses = []
    
    if args.demo:
        console.print("[cyan]📦 Loading demo data...[/cyan]")
        raw_requests, raw_responses = load_sample_data()
        console.print(f"[green]✓[/green] Loaded {len(raw_requests)} sample requests and {len(raw_responses)} responses")
    
    elif args.request and args.response:
        console.print("[cyan]📂 Loading from files...[/cyan]")
        raw_requests = [load_from_file(args.request)]
        raw_responses = [load_from_file(args.response)]
        console.print(f"[green]✓[/green] Loaded request and response")
    
    elif args.input:
        input_path = Path(args.input)
        
        if input_path.is_dir():
            console.print(f"[cyan]📂 Loading from directory: {args.input}[/cyan]")
            raw_requests, raw_responses = load_from_directory(args.input)
            console.print(f"[green]✓[/green] Loaded {len(raw_requests)} requests and {len(raw_responses)} responses")
        
        elif input_path.is_file():
            console.print(f"[cyan]📂 Loading from file: {args.input}[/cyan]")
            # Assume it's a request, look for corresponding response
            raw_requests = [load_from_file(args.input)]
            
            # Try to find response file
            resp_file = str(input_path).replace('request', 'response')
            if Path(resp_file).exists():
                raw_responses = [load_from_file(resp_file)]
                console.print(f"[green]✓[/green] Loaded request and response")
            else:
                console.print("[yellow]Warning: No response file found[/yellow]")
                raw_responses = []
        else:
            console.print(f"[red]Error: {args.input} not found[/red]")
            sys.exit(1)
    
    else:
        console.print("[yellow]No input specified. Use --demo for demo data or --help for usage.[/yellow]")
        parser.print_help()
        sys.exit(1)
    
    # Validate data
    if not raw_requests:
        console.print("[red]Error: No HTTP requests loaded[/red]")
        sys.exit(1)
    
    # Parse HTTP data
    state = parse_http_data(raw_requests, raw_responses)
    state["analysis_context"] = {"target": args.target}
    
    # Run analysis workflow
    final_state = run_analysis(state)
    
    # Display summary
    display_summary(final_state)
    
    # Generate report
    report_path = generate_report(final_state, args.output)
    
    # Final message
    console.print(Panel.fit(
        f"[bold green]Analysis Complete![/bold green]\n\n"
        f"Report: [cyan]{report_path}[/cyan]",
        border_style="green"
    ))


if __name__ == "__main__":
    main()
