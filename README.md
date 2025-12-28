# AI-Powered Authentication Logic Analyzer

A security testing tool that uses AI agents to analyze authentication flows and detect logic vulnerabilities.

## Architecture

### CrewAI Agents
- **Request Parser Agent**: Processes Burp Suite requests and extracts authentication flows
- **Auth Analyzer Agent**: Analyzes authentication mechanisms and patterns
- **Vulnerability Detector Agent**: Identifies logic flaws and security issues
- **Report Generator Agent**: Creates comprehensive security reports

### LangGraph Orchestration
- Coordinates agent workflow
- Manages state transitions
- Handles complex decision trees

## Project Structure

```
cred_attack_ai/
├── src/
│   ├── agents/          # CrewAI agent definitions
│   ├── workflows/       # LangGraph orchestration logic
│   ├── tools/           # Agent tools and utilities
│   └── models/          # Data schemas and models
├── config/              # Configuration files
├── tests/               # Unit and integration tests
└── examples/            # Sample inputs (Burp requests)
```

## Setup

```bash
pip install -r requirements.txt
```

## Usage

*Implementation pending*

## Requirements

- Python 3.10+
- CrewAI
- LangGraph
- OpenAI API key or compatible LLM provider

## Security Note

This tool is for authorized security testing only. Use responsibly.
