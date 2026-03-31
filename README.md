# MCP Security Scanner

Security testing tools for AI agents and MCP servers. Install as an MCP server in Cursor, Claude Desktop, or any MCP client.

12 tools. Zero dependencies. One install.

## Install

Add to your MCP client config:

**Cursor** (`.cursor/mcp.json`):
```json
{
  "mcpServers": {
    "security": {
      "command": "npx",
      "args": ["@cybersecai/mcp-security-scanner"]
    }
  }
}
```

**Claude Desktop** (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "security": {
      "command": "npx",
      "args": ["@cybersecai/mcp-security-scanner"]
    }
  }
}
```

Then ask your AI:

- "Scan the MCP server at dvmcp.co.uk for vulnerabilities"
- "Is it safe to pip install litellm?"
- "Check if langchain-ai/langchain repo is safe"
- "Audit my package.json for security issues"

## Tools

### MCP Server Security

| Tool | What it does |
|------|-------------|
| `scan_server` | Full OWASP MCP Top 10 scan of any MCP server. 10 checks including auth bypass, command injection, SSRF, rug pulls, tool poisoning, unsigned messages, replay attacks, path traversal, rate limiting. |
| `assess_risk` | Risk-rate an MCP server's exposed tools before connecting. Scores each tool as CRITICAL/HIGH/MEDIUM/LOW/SAFE. |
| `check_call` | Runtime GO/CAUTION/BLOCK decision before any MCP tool call. Checks arguments for injection, tool name for sensitivity, and package for CVEs. |
| `check_args` | Check if tool call arguments contain injection patterns (command injection, SQL injection, path traversal, SSRF, prompt injection). |

### Supply Chain Security

| Tool | What it does |
|------|-------------|
| `safe_to_install` | Check any npm or PyPI package before installing. Returns SAFE/CAUTION/DANGER verdict with full vulnerability details. |
| `check_cves` | Check any package for known vulnerabilities. |
| `audit_dependencies` | Audit all dependencies in a package.json or requirements.txt file at once. |
| `check_repo` | Check if a GitHub repo is trustworthy. Analyses age, stars, activity, license, and security signals. Returns a trust score out of 100. |

### Compliance

| Tool | What it does |
|------|-------------|
| `compliance_scan` | Scan an MCP server against EU AI Act, OWASP Agentic AI Top 10, and OWASP MCP Top 10. Returns unified compliance report with scores, failures, and remediation. |
| `cis_benchmark` | Run the CIS MCP Security Benchmark (Community Draft, 22 controls, 6 sections) against any MCP server. L1/L2 profiles, CIS Controls v8.1 mappings, and gap analysis. |

### Threat Intelligence

| Tool | What it does |
|------|-------------|
| `check_agent` | Check if an AI agent, MCP server, or package has known threat entries. Queries the Agent Threat Database for real-world incidents including data exfiltration, credential theft, and supply chain attacks. |

## Examples

**"Is it safe to install litellm?"**
```
Verdict: DANGER -- DO NOT INSTALL
This package contains confirmed MALICIOUS CODE.
17 vulnerabilities including credential harvesting malware.
```

**"Scan dvmcp.co.uk for vulnerabilities"**
```
Results: 0 passed, 10 failed (3 critical, 4 high)
[FAIL] Command Injection (CRITICAL)
[FAIL] SSRF (HIGH)
[FAIL] Authentication Bypass (HIGH)
...
```

**"Should I call run_command with argument '; rm -rf /'"**
```
BLOCK -- Do not execute this call.
- CRITICAL: Command injection detected
- CRITICAL: Tool 'run_command' is a sensitive tool (shell execution)
```

**"Is langchain-ai/langchain repo safe?"**
```
Trust Score: 80/100 (SAFE)
131,361 stars | 41 months old | MIT license | Recently active
```

## Test It

Scan our deliberately vulnerable MCP server:

```
"Scan the MCP server at https://dvmcp.co.uk for security issues"
```

Or try the one-click scan at [dvmcp.co.uk](https://dvmcp.co.uk).

## Standards

- [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html) (Section 7)
- [IETF draft-sharif-mcps-secure-mcp](https://datatracker.ietf.org/doc/draft-sharif-mcps-secure-mcp/)
- OWASP MCP Top 10

## Author

Raza Sharif, [CyberSecAI Ltd](https://cybersecai.co.uk)

## License

Business Source License 1.1 (BSL). Free for non-commercial use. Commercial use requires a license from CyberSecAI Ltd. See [LICENSE](LICENSE) for details.
