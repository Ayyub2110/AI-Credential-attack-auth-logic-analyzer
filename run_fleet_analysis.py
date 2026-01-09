"""
Quick analysis script for Fleet Tracking Portal
Uses the working demo infrastructure with your real data
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.tools.burp_parser import HTTPParser
from src.workflows.analysis_graph import (
    create_auth_analysis_graph,
    initialize_state,
)
from src.agents.report_generator_agent import PentestReportGenerator
from rich.console import Console
from rich.panel import Panel

console = Console()

# Read your real request and response
with open("test_data/request_1_login.txt", "r") as f:
    fleet_request = f.read()

with open("test_data/response_1_login.txt", "r") as f:
    fleet_response = f.read()

console.print(Panel.fit(
    "[bold cyan]Fleet Tracking Portal - Authentication Analysis[/bold cyan]",
    border_style="cyan"
))

console.print("\n📦 Loading Fleet Tracking data...\n")
console.print(f"✓ Request: POST /fleettracking/login/company")
console.print(f"✓ Response: HTTP 200 (30 bytes)")

# Parse the data
console.print("\n📝 Parsing HTTP data...\n")
parser = HTTPParser()

requests = [fleet_request]
responses = [fleet_response]

parsed_requests = []
parsed_responses = []

for i, req in enumerate(requests, 1):
    try:
        parsed = parser.parse_request(req)
        parsed_requests.append(parsed)
        method = parsed.get('method', 'UNKNOWN')
        path = parsed.get('path', 'unknown')
        console.print(f"✓ Parsed request {i}: {method} {path}")
    except Exception as e:
        console.print(f"[red]✗ Error parsing request {i}: {e}[/red]")

for i, resp in enumerate(responses, 1):
    try:
        parsed = parser.parse_response(resp)
        parsed_responses.append(parsed)
        status = parsed.get('status_code', 'unknown')
        body_len = len(parsed.get('body', ''))
        console.print(f"✓ Parsed response {i}: {status} ({body_len} bytes)")
    except Exception as e:
        console.print(f"[red]✗ Error parsing response {i}: {e}[/red]")

# Initialize state
state = initialize_state(
    raw_requests=requests,
    raw_responses=responses,
    context={"target_name": "Fleet Tracking Portal (qa-one.thegoldenelement.com)"}
)

# Create and run the analysis graph
console.print("\n🔬 Starting authentication analysis workflow...\n")
graph = create_auth_analysis_graph()

try:
    final_state = graph.invoke(state)
    
    console.print("\n" + "="*70)
    console.print(Panel.fit(
        "[bold green]✓ Analysis complete[/bold green]",
        border_style="green"
    ))
    console.print("="*70 + "\n")
    
    # Generate report
    console.print("📊 Generating penetration testing report...\n")
    report_gen = PentestReportGenerator()
    
    report_path = report_gen.generate_markdown_report(
        state=final_state,
        target_name="Fleet Tracking Portal",
        target_url="https://qa-one.thegoldenelement.com/fleettracking/login/company"
    )
    
    console.print(f"[bold green]✓ Report saved to: {report_path}[/bold green]")
    console.print("\n" + "="*70)
    console.print(Panel.fit(
        f"[bold]Analysis Complete![/bold]\n\n"
        f"Report: [cyan]{report_path}[/cyan]",
        border_style="green"
    ))
    console.print("="*70 + "\n")
    
except Exception as e:
    console.print(f"\n[bold red]Error during analysis: {e}[/bold red]")
    import traceback
    traceback.print_exc()
