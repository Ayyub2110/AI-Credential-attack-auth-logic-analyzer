# Step-by-Step Testing Guide

## Authentication Logic Analyzer - Real-World Testing

---

## Prerequisites

✅ Python 3.10+ installed  
✅ Burp Suite (Free or Pro)  
✅ Target application with authentication  
✅ API key for OpenAI or compatible LLM

---

## Step 1: Setup Environment

### 1.1 Verify Installation

```bash
cd "C:\Users\Ayub Ansari\Documents\projects\cred_attack_ai"

# Check Python version
python --version
# Should show 3.10 or higher

# Verify packages installed
python -c "import crewai, langgraph, rich; print('✓ All packages installed')"
```

### 1.2 Configure API Keys

```bash
# Copy the example environment file
copy .env.example .env

# Edit .env file and add your API key
notepad .env
```

In `.env`, set:
```
OPENAI_API_KEY=sk-your-actual-api-key-here
OPENAI_MODEL=gpt-4-turbo-preview
LOG_LEVEL=INFO
```

---

## Step 2: Collect HTTP Requests from Burp Suite

### 2.1 Capture Authentication Flow

1. **Open Burp Suite** and configure browser proxy
2. **Navigate to target application** and complete authentication:
   - Login with invalid username → copy request/response
   - Login with valid username, wrong password → copy request/response
   - Login successfully → copy request/response
   - Access MFA challenge (if applicable) → copy request/response
   - Access protected resource → copy request/response

### 2.2 Export Requests from Burp

**Method A: Manual Copy (Recommended)**

1. In Burp Suite, go to **Proxy → HTTP History**
2. Find your login request
3. **Right-click → Copy to file** or select request and:
   - Go to **Raw** tab
   - Copy entire request including headers and body
4. Paste into a text file

**Example: Save to `test_data/request_1.txt`**
```
POST /api/auth/login HTTP/1.1
Host: example.com
Content-Type: application/json
Content-Length: 45

{"username":"test","password":"test123"}
```

5. Do the same for the **Response** tab → save to `test_data/response_1.txt`

### 2.3 Organize Your Test Data

Create this structure:
```
cred_attack_ai/
└── test_data/
    ├── request_1_invalid_user.txt      # Invalid username attempt
    ├── response_1_invalid_user.txt
    ├── request_2_valid_user_wrong_pw.txt  # Valid user, wrong password
    ├── response_2_valid_user_wrong_pw.txt
    ├── request_3_success.txt            # Successful login
    ├── response_3_success.txt
    ├── request_4_mfa.txt                # MFA challenge (if applicable)
    ├── response_4_mfa.txt
    ├── request_5_protected.txt          # Access protected resource
    └── response_5_protected.txt
```

---

## Step 3: Test with Demo Data First

Before using real data, verify everything works:

```bash
# Run with built-in demo data
python main.py --demo
```

**Expected Output:**
```
╔═══════════════════════════════════════════════════════════════════╗
║   AI-Powered Authentication Logic Analyzer                       ║
╚═══════════════════════════════════════════════════════════════════╝

📦 Loading demo data...
✓ Loaded 5 sample requests and 5 responses

📝 Parsing HTTP data...
✓ Parsed request 1: POST /api/auth/login
✓ Parsed request 2: POST /api/auth/login
...

🔬 Starting authentication analysis workflow...
🔍 Running AuthLogicAgent...
🔍 Running UsernameEnumAgent...
...

📊 Generating penetration testing report...
✓ Report saved to: reports/pentest_report_20251227_143052.md
```

**Action:** Open the generated report in `reports/` folder to see the format

---

## Step 4: Analyze Your Real Application

### 4.1 Using Directory Input (Multiple Requests)

```bash
# Analyze all requests/responses in a directory
python main.py --input test_data/ --target "example.com"
```

This will:
- Auto-detect all `*request*.txt` and `*response*.txt` files
- Parse and analyze them
- Generate a report

### 4.2 Using Single Request/Response

```bash
# Analyze a single request/response pair
python main.py --request test_data/request_1.txt --response test_data/response_1.txt --target "example.com"
```

### 4.3 Specify Output Location

```bash
# Save report to specific location
python main.py --input test_data/ --output my_pentest_report.md --target "client-app.com"
```

---

## Step 5: Review the Analysis Report

### 5.1 Open the Report

```bash
# Open in default Markdown viewer
start reports\pentest_report_*.md

# Or open in VS Code
code reports\pentest_report_*.md
```

### 5.2 Key Sections to Review

1. **Executive Summary** - Overall risk rating and vulnerability count
2. **Authentication Flow Summary** - Visual flow diagram
3. **Username Enumeration** - Check for information disclosure
4. **Brute Force Feasibility** - Rate limiting and lockout analysis
5. **MFA Analysis** - Logic flaws and bypass opportunities
6. **Token Security** - JWT vulnerabilities
7. **Remediation Recommendations** - Prioritized fixes

---

## Step 6: Real-World Workflow Example

### Scenario: Testing a Banking App Login

```bash
# 1. Create test directory
mkdir test_data

# 2. In Burp Suite, capture these flows:
#    - Login with non-existent user
#    - Login with existing user, wrong password  
#    - Login with correct credentials
#    - MFA challenge
#    - Access account balance (protected resource)

# 3. Export each request/response pair from Burp to test_data/

# 4. Run analysis
python main.py --input test_data/ --target "BankingApp Portal" --output banking_pentest.md

# 5. Review report
code banking_pentest.md
```

---

## Step 7: Interpreting Results

### What to Look For:

**🔴 Critical Findings:**
- Username enumeration detected
- MFA bypass possible
- JWT with `alg=none`
- Tokens valid after logout

**🟡 Important Findings:**
- No rate limiting
- Weak password policy
- Missing token claims (exp, aud, iss)

**✅ Good Security:**
- Consistent error messages
- Rate limiting enabled
- MFA enforced server-side
- Strong token validation

---

## Step 8: Advanced Usage

### 8.1 Multiple Test Scenarios

```bash
# Test different user types
python main.py --input test_data/admin_flow/ --target "Admin Portal"
python main.py --input test_data/user_flow/ --target "User Portal"
```

### 8.2 Comparing Before/After Fixes

```bash
# Before remediation
python main.py --input test_data/before/ --output before_fix.md

# After remediation
python main.py --input test_data/after/ --output after_fix.md

# Compare reports
```

### 8.3 Batch Analysis

Create a script `analyze_all.ps1`:
```powershell
$targets = @("app1", "app2", "app3")

foreach ($target in $targets) {
    Write-Host "Analyzing $target..."
    python main.py --input "test_data/$target/" --target $target --output "reports/$target.md"
}
```

---

## Troubleshooting

### Issue: "No HTTP requests loaded"

**Solution:** Verify file format. Request should start with:
```
POST /path HTTP/1.1
Host: example.com
...
```

### Issue: "Import errors" in VS Code

**Solution:** 
```bash
# Restart Python language server
# Ctrl+Shift+P → "Python: Restart Language Server"
```

### Issue: API rate limits

**Solution:** Use local LLM or adjust rate limits in code

### Issue: Large Burp exports

**Solution:** Filter and export only authentication-related requests

---

## Best Practices

### 1. Test in Controlled Environment
- Use test accounts, not production
- Get proper authorization
- Document permission to test

### 2. Organize Test Data
- Use descriptive filenames
- Separate different flows into folders
- Keep raw Burp exports as backup

### 3. Incremental Testing
- Start with demo data
- Test with 1-2 real requests
- Scale to full authentication flow

### 4. Version Control
- **DO NOT** commit `.env` or API keys
- **DO NOT** commit sensitive test data
- Use `.gitignore` (already configured)

### 5. Report Handling
- Mark reports as CONFIDENTIAL
- Share securely with client
- Follow responsible disclosure

---

## Quick Reference Commands

```bash
# Demo run
python main.py --demo

# Analyze directory
python main.py --input test_data/ --target "MyApp"

# Single request pair
python main.py --request req.txt --response resp.txt

# Custom output
python main.py --demo --output my_report.md

# Get help
python main.py --help
```

---

## Next Steps

1. ✅ Test with demo data (`python main.py --demo`)
2. ✅ Capture 2-3 real requests from Burp Suite
3. ✅ Save to `test_data/` directory
4. ✅ Run analysis on real data
5. ✅ Review generated report
6. ✅ Share findings with team

---

## Need Help?

- Check the README.md for architecture details
- Review agent files in `src/agents/` for capabilities
- Examine workflow in `src/workflows/analysis_graph.py`
- Look at sample data structure in demo mode

**Good luck with your security testing! 🔒**
