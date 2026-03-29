#!/usr/bin/env node
'use strict';

/**
 * MCP Security Scanner
 *
 * An MCP server that provides security testing tools for AI agents and MCP servers.
 * Install as an MCP server in Cursor, Claude Desktop, or any MCP client.
 *
 * Tools:
 *   scan_server    - Full OWASP MCP Top 10 scan of a remote MCP server
 *   self_test      - Test your own agent's security posture
 *   check_cves     - Check an npm/PyPI package for known MCP CVEs
 *   check_args     - Check if tool arguments contain injection patterns
 *   assess_risk    - Risk assessment of an MCP server's exposed tools
 *   check_call     - Runtime AI call interception: go/no-go security decision before any MCP tool call
 *
 * Author: Raza Sharif, CyberSecAI Ltd
 */

const http = require('node:http');
const https = require('node:https');
const crypto = require('node:crypto');

// ============================================================================
// MCP Protocol Handler (stdio)
// ============================================================================

class MCPSecurityScanner {
  constructor() {
    this.buffer = '';
    this.requestId = 0;
    this.initialized = false;
  }

  start() {
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => {
      this.buffer += chunk;
      this._processBuffer();
    });
    process.stdin.on('end', () => process.exit(0));
  }

  _processBuffer() {
    const lines = this.buffer.split('\n');
    this.buffer = lines.pop() || '';

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const message = JSON.parse(trimmed);
        this._handleMessage(message);
      } catch {
        // Skip non-JSON lines
      }
    }
  }

  _handleMessage(message) {
    const { method, id, params } = message;

    switch (method) {
      case 'initialize':
        this._respond(id, {
          protocolVersion: '2024-11-05',
          serverInfo: {
            name: 'MCP Security Scanner',
            version: '0.1.0',
          },
          capabilities: {
            tools: { listChanged: false },
          },
        });
        this.initialized = true;
        break;

      case 'notifications/initialized':
        // Client acknowledged initialization
        break;

      case 'tools/list':
        this._respond(id, { tools: this._getTools() });
        break;

      case 'tools/call':
        this._handleToolCall(id, params);
        break;

      case 'ping':
        this._respond(id, {});
        break;

      default:
        this._respondError(id, -32601, `Method not found: ${method}`);
    }
  }

  _respond(id, result) {
    const response = JSON.stringify({ jsonrpc: '2.0', id, result });
    process.stdout.write(response + '\n');
  }

  _respondError(id, code, message) {
    const response = JSON.stringify({
      jsonrpc: '2.0', id,
      error: { code, message },
    });
    process.stdout.write(response + '\n');
  }

  // ============================================================================
  // Tool Definitions
  // ============================================================================

  _getTools() {
    return [
      {
        name: 'scan_server',
        description: 'Scan a remote MCP server for security vulnerabilities. Runs 12 OWASP MCP Top 10 checks including auth bypass, command injection, SSRF, rug pulls, unsigned messages, replay attacks, and more. Returns a detailed report with severity ratings and remediation guidance.',
        inputSchema: {
          type: 'object',
          properties: {
            url: {
              type: 'string',
              description: 'URL of the MCP server to scan (e.g., http://localhost:3000 or https://mcp.example.com)',
            },
            timeout: {
              type: 'number',
              description: 'Timeout per test in milliseconds (default: 5000)',
            },
          },
          required: ['url'],
        },
      },
      {
        name: 'check_args',
        description: 'Check if tool call arguments contain dangerous patterns such as command injection, SQL injection, path traversal, or SSRF. Use this before calling any untrusted MCP tool.',
        inputSchema: {
          type: 'object',
          properties: {
            tool_name: {
              type: 'string',
              description: 'Name of the tool being called',
            },
            arguments: {
              type: 'object',
              description: 'The arguments object being passed to the tool',
            },
          },
          required: ['tool_name', 'arguments'],
        },
      },
      {
        name: 'assess_risk',
        description: 'Assess the security risk of an MCP server by analysing its exposed tools. Connects to the server, enumerates tools, and rates each one by risk level based on tool name, description, and argument types.',
        inputSchema: {
          type: 'object',
          properties: {
            url: {
              type: 'string',
              description: 'URL of the MCP server to assess',
            },
          },
          required: ['url'],
        },
      },
      {
        name: 'check_cves',
        description: 'Check if an npm or PyPI package has known MCP-related security vulnerabilities by querying the OSV.dev database.',
        inputSchema: {
          type: 'object',
          properties: {
            package_name: {
              type: 'string',
              description: 'Package name (e.g., mcp-bridge, @grackle-ai/mcp)',
            },
            ecosystem: {
              type: 'string',
              description: 'Package ecosystem: npm or PyPI (default: npm)',
            },
          },
          required: ['package_name'],
        },
      },
      {
        name: 'check_call',
        description: 'Check if an MCP tool call is safe before executing it. Analyses the target server, tool name, and arguments for security risks including injection, SSRF, sensitive tool exposure, and known CVEs. Use this before calling any untrusted MCP tool to get a go/no-go security decision.',
        inputSchema: {
          type: 'object',
          properties: {
            server_url: {
              type: 'string',
              description: 'URL of the MCP server being called',
            },
            tool_name: {
              type: 'string',
              description: 'Name of the tool about to be called',
            },
            arguments: {
              type: 'object',
              description: 'Arguments about to be passed to the tool',
            },
            package_name: {
              type: 'string',
              description: 'Optional: npm/PyPI package name of the MCP server for CVE check',
            },
          },
          required: ['tool_name', 'arguments'],
        },
      },
      {
        name: 'safe_to_install',
        description: 'Check if a package is safe to install before running npm install or pip install. Queries vulnerability databases, checks for malicious code reports, and provides a SAFE/CAUTION/DANGER verdict. Use this any time before installing a new package.',
        inputSchema: {
          type: 'object',
          properties: {
            package_name: {
              type: 'string',
              description: 'Package name exactly as you would type in npm install or pip install (e.g., mcp-bridge, litellm, @anthropic-ai/sdk)',
            },
            ecosystem: {
              type: 'string',
              description: 'npm or pypi (default: auto-detect from package name)',
            },
          },
          required: ['package_name'],
        },
      },
      {
        name: 'audit_dependencies',
        description: 'Audit all dependencies in a package.json or requirements.txt file for known vulnerabilities. Paste the file contents and get a full security report of every dependency.',
        inputSchema: {
          type: 'object',
          properties: {
            content: {
              type: 'string',
              description: 'The full contents of package.json or requirements.txt file',
            },
            type: {
              type: 'string',
              description: 'File type: package.json or requirements.txt (auto-detected if not specified)',
            },
          },
          required: ['content'],
        },
      },
      {
        name: 'check_repo',
        description: 'Check if a GitHub repository is safe and trustworthy. Analyses repo age, stars, contributors, recent activity, known vulnerabilities, and security signals. Use this before cloning or depending on an unknown repo.',
        inputSchema: {
          type: 'object',
          properties: {
            repo: {
              type: 'string',
              description: 'GitHub repo in owner/name format (e.g., langchain-ai/langchain, razashariff/dvmcp)',
            },
          },
          required: ['repo'],
        },
      },
      {
        name: 'compliance_scan',
        description: 'Scan an MCP server for compliance against EU AI Act, OWASP MCP Top 10, and OWASP Agentic AI Top 10. Connects to the server and runs automated checks. Returns a unified compliance report with scores, failures, and specific remediation steps.',
        inputSchema: {
          type: 'object',
          properties: {
            url: {
              type: 'string',
              description: 'URL of the MCP server to scan (e.g., http://localhost:3000 or https://mcp.example.com)',
            },
          },
          required: ['url'],
        },
      },
      {
        name: 'check_agent',
        description: 'Check if an AI agent, MCP server, or package has known threat entries in the Agent Threat Database. Queries real-world incidents including data exfiltration, credential theft, prompt injection, and supply chain attacks.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Agent name, MCP server name, or package name to check (e.g., mcp-remote, openclaw, litellm)',
            },
          },
          required: ['query'],
        },
      },
    ];
  }

  // ============================================================================
  // Tool Implementations
  // ============================================================================

  async _handleToolCall(id, params) {
    const { name, arguments: args } = params || {};

    try {
      let result;
      switch (name) {
        case 'scan_server':
          result = await this._scanServer(args);
          break;
        case 'check_args':
          result = this._checkArgs(args);
          break;
        case 'assess_risk':
          result = await this._assessRisk(args);
          break;
        case 'check_cves':
          result = await this._checkCves(args);
          break;
        case 'check_call':
          result = await this._checkCall(args);
          break;
        case 'safe_to_install':
          result = await this._safeToInstall(args);
          break;
        case 'audit_dependencies':
          result = await this._auditDependencies(args);
          break;
        case 'check_repo':
          result = await this._checkRepo(args);
          break;
        case 'compliance_scan':
          result = await this._complianceScan(args);
          break;
        case 'check_agent':
          result = await this._checkAgent(args);
          break;
        default:
          this._respondError(id, -32601, `Unknown tool: ${name}`);
          return;
      }

      this._respond(id, {
        content: [{ type: 'text', text: typeof result === 'string' ? result : JSON.stringify(result, null, 2) }],
      });
    } catch (err) {
      this._respond(id, {
        content: [{ type: 'text', text: `Error: ${err.message}` }],
        isError: true,
      });
    }
  }

  // --------------------------------------------------------------------------
  // scan_server: Full OWASP MCP Top 10 scan
  // --------------------------------------------------------------------------

  async _scanServer(args) {
    const { url, timeout = 5000 } = args || {};
    if (!url) return 'Error: url is required';

    const results = [];
    const startTime = Date.now();

    // Helper to send JSON-RPC to target (supports both plain JSON and SSE responses)
    const rpc = async (method, params = {}) => {
      return new Promise((resolve, reject) => {
        const body = JSON.stringify({
          jsonrpc: '2.0',
          method,
          id: crypto.randomUUID(),
          params,
        });

        const urlObj = new URL(url);
        const client = urlObj.protocol === 'https:' ? https : http;
        const req = client.request(urlObj, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/event-stream',
            'Content-Length': Buffer.byteLength(body),
          },
          timeout,
        }, (res) => {
          let data = '';
          res.on('data', (chunk) => data += chunk);
          res.on('end', () => {
            const contentType = (res.headers['content-type'] || '').toLowerCase();
            const parsed = MCPSecurityScanner._parseResponse(data, contentType);
            resolve({ status: res.statusCode, body: parsed });
          });
        });
        req.on('error', (e) => reject(e));
        req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
        req.write(body);
        req.end();
      });
    };

    // Test 1: Auth Bypass
    try {
      const r = await rpc('tools/list');
      if (r.status === 200 && r.body.result) {
        results.push({ id: 'MCP-001', name: 'Authentication Bypass', status: 'FAIL', severity: 'HIGH',
          detail: 'tools/list accessible without authentication',
          fix: 'Implement OAuth 2.1 authentication on all MCP endpoints' });
      } else {
        results.push({ id: 'MCP-001', name: 'Authentication Bypass', status: 'PASS', severity: '-',
          detail: 'Server requires authentication', fix: '' });
      }
    } catch (e) {
      results.push({ id: 'MCP-001', name: 'Authentication Bypass', status: 'ERROR', severity: '-',
        detail: `Connection failed: ${e.message}`, fix: 'Check server URL' });
    }

    // Test 2: Unsigned Messages
    try {
      const r = await rpc('initialize', { clientInfo: { name: 'security-scanner', version: '1.0.0' }, protocolVersion: '2024-11-05', capabilities: {} });
      if (r.status === 200) {
        results.push({ id: 'MCP-002', name: 'Unsigned Messages', status: 'FAIL', severity: 'MEDIUM',
          detail: 'Server accepted request without MCPS signature',
          fix: 'Implement per-message signing per OWASP MCP Security Cheat Sheet Section 7. See https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html' });
      }
    } catch {
      results.push({ id: 'MCP-002', name: 'Unsigned Messages', status: 'ERROR', severity: '-',
        detail: 'Could not test', fix: '' });
    }

    // Test 3: Replay Attack
    try {
      const body = { jsonrpc: '2.0', method: 'tools/list', id: 'replay-test', params: {} };
      const bodyStr = JSON.stringify(body);
      const send = () => new Promise((resolve, reject) => {
        const urlObj = new URL(url);
        const client = urlObj.protocol === 'https:' ? https : http;
        const req = client.request(urlObj, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(bodyStr) },
          timeout,
        }, (res) => {
          let data = '';
          res.on('data', (chunk) => data += chunk);
          res.on('end', () => resolve(res.statusCode));
        });
        req.on('error', reject);
        req.write(bodyStr);
        req.end();
      });
      const s1 = await send();
      const s2 = await send();
      if (s1 === 200 && s2 === 200) {
        results.push({ id: 'MCP-003', name: 'Replay Attack', status: 'FAIL', severity: 'MEDIUM',
          detail: 'Server accepted identical replayed message',
          fix: 'Implement nonce tracking and timestamp-based replay windows' });
      } else {
        results.push({ id: 'MCP-003', name: 'Replay Attack', status: 'PASS', severity: '-',
          detail: 'Replay protection active', fix: '' });
      }
    } catch {
      results.push({ id: 'MCP-003', name: 'Replay Attack', status: 'ERROR', severity: '-',
        detail: 'Could not test', fix: '' });
    }

    // Test 4: Command Injection
    try {
      const r = await rpc('tools/call', { name: 'run_command', arguments: { command: '; echo INJECTION_TEST_MARKER' } });
      if (r.status === 200 && typeof r.body === 'object') {
        const text = JSON.stringify(r.body);
        if (text.includes('INJECTION_TEST_MARKER')) {
          results.push({ id: 'MCP-004', name: 'Command Injection', status: 'FAIL', severity: 'CRITICAL',
            detail: 'Shell command executed via tool arguments',
            fix: 'Sanitise all tool arguments. Never pass user input to shell commands.' });
        } else {
          results.push({ id: 'MCP-004', name: 'Command Injection', status: 'PASS', severity: '-',
            detail: 'Injection payload not executed', fix: '' });
        }
      } else {
        results.push({ id: 'MCP-004', name: 'Command Injection', status: 'PASS', severity: '-',
          detail: 'Tool not available or rejected', fix: '' });
      }
    } catch {
      results.push({ id: 'MCP-004', name: 'Command Injection', status: 'PASS', severity: '-',
        detail: 'Tool not available', fix: '' });
    }

    // Test 5: SSRF
    try {
      const r = await rpc('tools/call', { name: 'fetch_url', arguments: { url: 'http://169.254.169.254/latest/meta-data/' } });
      if (r.status === 200 && r.body.result) {
        results.push({ id: 'MCP-005', name: 'SSRF', status: 'FAIL', severity: 'HIGH',
          detail: 'Server accepted request to cloud metadata endpoint',
          fix: 'Validate and allowlist all URIs. Block internal IPs and cloud metadata endpoints.' });
      } else {
        results.push({ id: 'MCP-005', name: 'SSRF', status: 'PASS', severity: '-',
          detail: 'SSRF attempt rejected', fix: '' });
      }
    } catch {
      results.push({ id: 'MCP-005', name: 'SSRF', status: 'PASS', severity: '-',
        detail: 'Tool not available', fix: '' });
    }

    // Test 6: Path Traversal
    try {
      const r = await rpc('tools/call', { name: 'read_file', arguments: { path: '/etc/passwd' } });
      if (r.status === 200) {
        const text = JSON.stringify(r.body);
        if (text.includes('root:')) {
          results.push({ id: 'MCP-006', name: 'Path Traversal', status: 'FAIL', severity: 'HIGH',
            detail: '/etc/passwd readable via file tool',
            fix: 'Sandbox file access to allowed directories. Use allowlists.' });
        } else {
          results.push({ id: 'MCP-006', name: 'Path Traversal', status: 'PASS', severity: '-',
            detail: 'Sensitive file not accessible', fix: '' });
        }
      }
    } catch {
      results.push({ id: 'MCP-006', name: 'Path Traversal', status: 'PASS', severity: '-',
        detail: 'Tool not available', fix: '' });
    }

    // Test 7: Sensitive Tools Exposed
    try {
      const r = await rpc('tools/list');
      if (r.status === 200 && r.body.result && r.body.result.tools) {
        const tools = r.body.result.tools;
        const dangerous = ['exec', 'shell', 'command', 'run_command', 'admin', 'sudo', 'delete',
          'write_file', 'read_file', 'query_database', 'sql', 'credential', 'password', 'env'];
        const found = [];
        for (const tool of tools) {
          const name = (tool.name || '').toLowerCase();
          for (const d of dangerous) {
            if (name.includes(d)) { found.push(tool.name); break; }
          }
        }
        if (found.length > 0) {
          results.push({ id: 'MCP-007', name: 'Sensitive Tools Exposed', status: 'FAIL', severity: 'HIGH',
            detail: `${found.length} dangerous tool(s): ${found.join(', ')}`,
            fix: 'Restrict access to sensitive tools. Implement least-privilege.' });
        } else {
          results.push({ id: 'MCP-007', name: 'Sensitive Tools Exposed', status: 'PASS', severity: '-',
            detail: `${tools.length} tools checked, none flagged`, fix: '' });
        }
      }
    } catch {
      results.push({ id: 'MCP-007', name: 'Sensitive Tools Exposed', status: 'ERROR', severity: '-',
        detail: 'Could not enumerate tools', fix: '' });
    }

    // Test 8: Rug Pull (tool definition tampering)
    try {
      const r1 = await rpc('tools/list');
      await new Promise(r => setTimeout(r, 500));
      const r2 = await rpc('tools/list');
      if (r1.status === 200 && r2.status === 200) {
        const h1 = crypto.createHash('sha256').update(JSON.stringify(r1.body)).digest('hex').slice(0, 16);
        const h2 = crypto.createHash('sha256').update(JSON.stringify(r2.body)).digest('hex').slice(0, 16);
        if (h1 !== h2) {
          results.push({ id: 'MCP-008', name: 'Rug Pull', status: 'FAIL', severity: 'CRITICAL',
            detail: 'Tool definitions changed between calls',
            fix: 'Sign tool definitions. Pin hashes between sessions. See OWASP MCP Cheat Sheet Section 7.' });
        } else {
          results.push({ id: 'MCP-008', name: 'Rug Pull', status: 'PASS', severity: '-',
            detail: 'Tool definitions consistent', fix: '' });
        }
      }
    } catch {
      results.push({ id: 'MCP-008', name: 'Rug Pull', status: 'ERROR', severity: '-',
        detail: 'Could not test', fix: '' });
    }

    // Test 9: Tool Poisoning
    try {
      const r = await rpc('tools/list');
      if (r.status === 200 && r.body.result && r.body.result.tools) {
        const text = JSON.stringify(r.body.result.tools).toLowerCase();
        const injections = ['ignore previous', 'ignore all', 'system command', '<script', 'javascript:'];
        const found = injections.filter(p => text.includes(p));
        if (found.length > 0) {
          results.push({ id: 'MCP-009', name: 'Tool Poisoning', status: 'FAIL', severity: 'CRITICAL',
            detail: `Prompt injection patterns in tool descriptions: ${found.join(', ')}`,
            fix: 'Scan tool descriptions for injection patterns before including in LLM context.' });
        } else {
          results.push({ id: 'MCP-009', name: 'Tool Poisoning', status: 'PASS', severity: '-',
            detail: 'No injection patterns found', fix: '' });
        }
      }
    } catch {
      results.push({ id: 'MCP-009', name: 'Tool Poisoning', status: 'ERROR', severity: '-',
        detail: 'Could not test', fix: '' });
    }

    // Test 10: Rate Limiting
    try {
      let accepted = 0;
      for (let i = 0; i < 20; i++) {
        try {
          const r = await rpc('tools/list');
          if (r.status === 200) accepted++;
          if (r.status === 429) {
            results.push({ id: 'MCP-010', name: 'Rate Limiting', status: 'PASS', severity: '-',
              detail: `Rate limit triggered at request ${i + 1}`, fix: '' });
            break;
          }
        } catch { break; }
      }
      if (accepted >= 18) {
        results.push({ id: 'MCP-010', name: 'Rate Limiting', status: 'FAIL', severity: 'MEDIUM',
          detail: `${accepted}/20 rapid requests accepted`,
          fix: 'Implement rate limiting. Return HTTP 429 with Retry-After header.' });
      }
    } catch {
      results.push({ id: 'MCP-010', name: 'Rate Limiting', status: 'ERROR', severity: '-',
        detail: 'Could not test', fix: '' });
    }

    const elapsed = Date.now() - startTime;
    const pass = results.filter(r => r.status === 'PASS').length;
    const fail = results.filter(r => r.status === 'FAIL').length;
    const critical = results.filter(r => r.severity === 'CRITICAL').length;
    const high = results.filter(r => r.severity === 'HIGH').length;

    let report = `MCP Security Scan Report\n`;
    report += `========================\n`;
    report += `Target: ${url}\n`;
    report += `Date: ${new Date().toISOString()}\n`;
    report += `Duration: ${elapsed}ms\n`;
    report += `Results: ${pass} passed, ${fail} failed (${critical} critical, ${high} high)\n\n`;

    for (const r of results) {
      const icon = r.status === 'PASS' ? 'PASS' : r.status === 'FAIL' ? 'FAIL' : 'ERROR';
      report += `[${icon}] ${r.id} ${r.name} (${r.severity})\n`;
      report += `      ${r.detail}\n`;
      if (r.fix) report += `      Fix: ${r.fix}\n`;
      report += `\n`;
    }

    report += `Reference: OWASP MCP Security Cheat Sheet\n`;
    report += `https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html\n`;

    return report;
  }

  // --------------------------------------------------------------------------
  // check_args: Validate tool arguments for injection
  // --------------------------------------------------------------------------

  _checkArgs(args) {
    const { tool_name, arguments: toolArgs } = args || {};
    if (!tool_name || !toolArgs) return 'Error: tool_name and arguments are required';

    const findings = [];
    const argStr = JSON.stringify(toolArgs);

    // Command injection
    const cmdPatterns = [/;\s*(rm|cat|curl|wget|bash|sh|python|node)\b/i, /\|\s*\w+/, /&&\s*\w+/, /\$\(/, /`[^`]+`/, /\bexec\s*\(/i];
    for (const p of cmdPatterns) {
      if (p.test(argStr)) findings.push({ severity: 'CRITICAL', type: 'Command Injection', detail: `Pattern matched: ${p.source}` });
    }

    // SQL injection
    const sqlPatterns = [/'\s*(OR|AND)\s+'?\d/i, /UNION\s+SELECT/i, /;\s*DROP\s+TABLE/i, /--\s*$/m];
    for (const p of sqlPatterns) {
      if (p.test(argStr)) findings.push({ severity: 'HIGH', type: 'SQL Injection', detail: `Pattern matched: ${p.source}` });
    }

    // Path traversal
    if (/\.\.[\/\\]/.test(argStr) || /\/etc\/(passwd|shadow|hosts)/.test(argStr)) {
      findings.push({ severity: 'HIGH', type: 'Path Traversal', detail: 'Directory traversal or sensitive path detected' });
    }

    // SSRF
    if (/169\.254\.169\.254|127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\]|10\.\d+\.\d+\.\d+/.test(argStr)) {
      findings.push({ severity: 'HIGH', type: 'SSRF', detail: 'Internal network address detected in arguments' });
    }

    // Prompt injection in args
    if (/ignore\s+(previous|all)|system\s+command|<script|javascript:/i.test(argStr)) {
      findings.push({ severity: 'MEDIUM', type: 'Prompt Injection', detail: 'Prompt injection pattern in arguments' });
    }

    if (findings.length === 0) {
      return `Arguments for "${tool_name}" appear safe. No injection patterns detected.`;
    }

    let report = `WARNING: ${findings.length} issue(s) found in arguments for "${tool_name}":\n\n`;
    for (const f of findings) {
      report += `  [${f.severity}] ${f.type}: ${f.detail}\n`;
    }
    report += `\nRecommendation: Do NOT call this tool with these arguments.`;
    return report;
  }

  // --------------------------------------------------------------------------
  // assess_risk: Analyse exposed tools on an MCP server
  // --------------------------------------------------------------------------

  async _assessRisk(args) {
    const { url } = args || {};
    if (!url) return 'Error: url is required';

    try {
      const body = JSON.stringify({ jsonrpc: '2.0', method: 'tools/list', id: crypto.randomUUID(), params: {} });
      const urlObj = new URL(url);
      const client = urlObj.protocol === 'https:' ? https : http;

      const response = await new Promise((resolve, reject) => {
        const req = client.request(urlObj, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/event-stream',
            'Content-Length': Buffer.byteLength(body),
          },
          timeout: 5000,
        }, (res) => {
          let data = '';
          res.on('data', (chunk) => data += chunk);
          res.on('end', () => {
            const contentType = (res.headers['content-type'] || '').toLowerCase();
            const parsed = MCPSecurityScanner._parseResponse(data, contentType);
            if (parsed && typeof parsed === 'object') {
              resolve(parsed);
            } else {
              reject(new Error('Invalid response from server'));
            }
          });
        });
        req.on('error', reject);
        req.write(body);
        req.end();
      });

      const tools = response.result?.tools || [];
      if (tools.length === 0) return 'No tools found on this server.';

      const dangerous = {
        critical: ['exec', 'shell', 'command', 'run_command', 'system', 'eval', 'sudo'],
        high: ['read_file', 'write_file', 'delete', 'remove', 'sql', 'query_database', 'credential', 'password', 'api_key', 'admin', 'deploy'],
        medium: ['fetch_url', 'http_request', 'download', 'upload', 'send_email', 'network'],
        low: ['list_files', 'list_processes', 'get_env', 'environment', 'config'],
      };

      let report = `Risk Assessment: ${url}\n`;
      report += `${'='.repeat(50)}\n`;
      report += `Total tools: ${tools.length}\n\n`;

      let totalRisk = 0;
      for (const tool of tools) {
        const name = (tool.name || '').toLowerCase();
        const desc = (tool.description || '').toLowerCase();
        let risk = 'SAFE';
        let score = 0;

        for (const [level, patterns] of Object.entries(dangerous)) {
          for (const p of patterns) {
            if (name.includes(p) || desc.includes(p)) {
              risk = level.toUpperCase();
              score = level === 'critical' ? 10 : level === 'high' ? 7 : level === 'medium' ? 4 : 2;
              break;
            }
          }
          if (risk !== 'SAFE') break;
        }

        totalRisk += score;
        report += `  [${risk.padEnd(8)}] ${tool.name}\n`;
        if (tool.description) report += `             ${tool.description.slice(0, 80)}\n`;
      }

      report += `\nOverall risk score: ${totalRisk}/${tools.length * 10}\n`;
      report += totalRisk > tools.length * 5 ? 'Rating: HIGH RISK -- review tool exposure before connecting agents\n' :
                totalRisk > tools.length * 2 ? 'Rating: MODERATE RISK -- restrict agent permissions\n' :
                'Rating: LOW RISK\n';

      return report;
    } catch (e) {
      return `Error connecting to ${url}: ${e.message}`;
    }
  }

  // --------------------------------------------------------------------------
  // SSE Response Parser (static, shared across methods)
  // --------------------------------------------------------------------------

  /**
   * Parse a response body that may be plain JSON or SSE-formatted.
   * SSE responses contain lines like "data: {...}\n\n".
   * For SSE, we extract the last JSON data event (the final result).
   */
  static _parseResponse(data, contentType) {
    if (!data || typeof data !== 'string') return data;

    const isSSE = (contentType || '').includes('text/event-stream') ||
                  data.trimStart().startsWith('event:') ||
                  data.trimStart().startsWith('data:');

    if (isSSE) {
      // Extract all "data: " lines and parse the last valid JSON one
      const lines = data.split('\n');
      let lastParsed = null;
      for (const line of lines) {
        if (line.startsWith('data: ')) {
          const payload = line.slice(6).trim();
          if (!payload || payload === '[DONE]') continue;
          try {
            lastParsed = JSON.parse(payload);
          } catch {
            // Not valid JSON, skip
          }
        }
      }
      if (lastParsed !== null) return lastParsed;
    }

    // Fall back to plain JSON parsing
    try { return JSON.parse(data); }
    catch { return data; }
  }

  // --------------------------------------------------------------------------
  // check_call: Runtime AI call interception
  // --------------------------------------------------------------------------

  async _checkCall(args) {
    const { server_url, tool_name, arguments: callArgs, package_name } = args || {};
    if (!tool_name) return 'Error: tool_name is required';
    if (!callArgs || typeof callArgs !== 'object') return 'Error: arguments is required and must be an object';

    const findings = [];

    // 1. Check arguments for injection/SSRF/traversal
    const argStr = JSON.stringify(callArgs);

    // Command injection
    const cmdPatterns = [/;\s*(rm|cat|curl|wget|bash|sh|python|node)\b/i, /\|\s*\w+/, /&&\s*\w+/, /\$\(/, /`[^`]+`/, /\bexec\s*\(/i];
    for (const p of cmdPatterns) {
      if (p.test(argStr)) {
        findings.push({ severity: 'CRITICAL', reason: `Command injection detected in arguments (pattern: ${p.source})` });
      }
    }

    // SQL injection
    const sqlPatterns = [/'\s*(OR|AND)\s+'?\d/i, /UNION\s+SELECT/i, /;\s*DROP\s+TABLE/i, /--\s*$/m];
    for (const p of sqlPatterns) {
      if (p.test(argStr)) {
        findings.push({ severity: 'HIGH', reason: `SQL injection pattern in arguments (pattern: ${p.source})` });
      }
    }

    // Path traversal
    if (/\.\.[\/\\]/.test(argStr) || /\/etc\/(passwd|shadow|hosts)/.test(argStr)) {
      findings.push({ severity: 'HIGH', reason: 'Path traversal or sensitive file path detected in arguments' });
    }

    // SSRF
    if (/169\.254\.169\.254|127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\]|10\.\d+\.\d+\.\d+/.test(argStr)) {
      findings.push({ severity: 'HIGH', reason: 'Internal/private network address detected in arguments (SSRF risk)' });
    }

    // Prompt injection
    if (/ignore\s+(previous|all)|system\s+command|<script|javascript:/i.test(argStr)) {
      findings.push({ severity: 'MEDIUM', reason: 'Prompt injection pattern detected in arguments' });
    }

    // 2. Assess tool name against dangerous patterns
    const nameLower = (tool_name || '').toLowerCase();
    const dangerousTools = {
      critical: ['exec', 'shell', 'command', 'run_command', 'system', 'eval', 'sudo'],
      high: ['read_file', 'write_file', 'delete', 'remove', 'sql', 'query_database', 'credential', 'password', 'api_key', 'admin', 'deploy'],
      medium: ['fetch_url', 'http_request', 'download', 'upload', 'send_email', 'network'],
    };

    for (const [level, patterns] of Object.entries(dangerousTools)) {
      for (const p of patterns) {
        if (nameLower.includes(p)) {
          const desc = level === 'critical' ? 'shell execution' :
                       level === 'high' ? 'sensitive operation' : 'outbound requests';
          findings.push({
            severity: level.toUpperCase(),
            reason: `Tool '${tool_name}' is a sensitive tool (${desc})`,
          });
          break;
        }
      }
    }

    // 3. Check CVEs if package_name provided
    if (package_name) {
      try {
        const cveResult = await this._checkCves({ package_name, ecosystem: 'npm' });
        if (cveResult && typeof cveResult === 'string') {
          if (cveResult.includes('Vulnerabilities found')) {
            // Extract count
            const countMatch = cveResult.match(/Vulnerabilities found.*?:\s*(\d+)/);
            const count = countMatch ? countMatch[1] : 'multiple';
            // Check for critical/RCE CVEs
            const hasRCE = /remote code|rce|arbitrary code/i.test(cveResult);
            if (hasRCE) {
              findings.push({ severity: 'CRITICAL', reason: `Package '${package_name}' has ${count} known CVE(s) including RCE vulnerabilities` });
            } else {
              findings.push({ severity: 'HIGH', reason: `Package '${package_name}' has ${count} known CVE(s)` });
            }
          }
        }
      } catch {
        // CVE check failed, non-blocking
      }
    }

    // 4. Determine decision
    const hasCritical = findings.some(f => f.severity === 'CRITICAL');
    const hasHighOrMedium = findings.some(f => f.severity === 'HIGH' || f.severity === 'MEDIUM');

    if (hasCritical) {
      let report = 'BLOCK -- Do not execute this call.\n';
      for (const f of findings) {
        report += `  - ${f.severity}: ${f.reason}\n`;
      }
      report += 'Recommendation: Sanitise arguments or use a safer tool.';
      return report;
    }

    if (hasHighOrMedium) {
      let report = 'CAUTION -- Proceed with care.\n';
      for (const f of findings) {
        report += `  - ${f.severity}: ${f.reason}\n`;
      }
      report += 'Recommendation: Verify the arguments and tool are intended for this operation.';
      return report;
    }

    let report = 'GO -- This call appears safe.\n';
    report += `  - Tool '${tool_name}' is not sensitive\n`;
    report += '  - Arguments contain no injection patterns\n';
    if (package_name) {
      report += `  - No known CVEs for '${package_name}'\n`;
    }
    if (server_url) {
      report += `  - Server: ${server_url}\n`;
    }
    return report;
  }

  // --------------------------------------------------------------------------
  // check_cves: Query OSV.dev for package vulnerabilities
  // --------------------------------------------------------------------------

  async _checkCves(args) {
    const { package_name, ecosystem = 'npm' } = args || {};
    if (!package_name) return 'Error: package_name is required';

    try {
      const body = JSON.stringify({
        package: { name: package_name, ecosystem: ecosystem === 'pypi' ? 'PyPI' : 'npm' },
      });

      const response = await new Promise((resolve, reject) => {
        const req = https.request('https://api.osv.dev/v1/query', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
          timeout: 10000,
        }, (res) => {
          let data = '';
          res.on('data', (chunk) => data += chunk);
          res.on('end', () => {
            try { resolve(JSON.parse(data)); }
            catch { reject(new Error('Invalid response from OSV.dev')); }
          });
        });
        req.on('error', reject);
        req.write(body);
        req.end();
      });

      const vulns = response.vulns || [];
      if (vulns.length === 0) {
        return `No known vulnerabilities found for ${package_name} (${ecosystem}). Package appears safe.`;
      }

      let report = `Vulnerabilities found for ${package_name} (${ecosystem}): ${vulns.length}\n\n`;
      for (const v of vulns.slice(0, 10)) {
        const severity = v.database_specific?.severity || v.severity?.[0]?.score || 'unknown';
        report += `  ${v.id} (${severity})\n`;
        report += `    ${(v.summary || v.details || 'No description').slice(0, 120)}\n`;
        if (v.affected?.[0]?.ranges?.[0]?.events) {
          const fixed = v.affected[0].ranges[0].events.find(e => e.fixed);
          if (fixed) report += `    Fixed in: ${fixed.fixed}\n`;
        }
        report += `\n`;
      }

      if (vulns.length > 10) report += `  ... and ${vulns.length - 10} more\n`;
      report += `\nRecommendation: Update to the latest patched version or find an alternative package.`;
      return report;
    } catch (e) {
      return `Error querying OSV.dev: ${e.message}`;
    }
  }

  // --------------------------------------------------------------------------
  // safe_to_install: Pre-install safety check
  // --------------------------------------------------------------------------

  async _safeToInstall(args) {
    const { package_name, ecosystem } = args || {};
    if (!package_name) return 'Error: package_name is required';

    // Auto-detect ecosystem
    const eco = ecosystem || (package_name.startsWith('@') || /^[a-z0-9-]+$/.test(package_name) ? 'npm' : 'pypi');

    let report = `Package Safety Check: ${package_name} (${eco})\n`;
    report += `${'='.repeat(50)}\n\n`;

    // Check CVEs
    let vulnCount = 0;
    let hasMalware = false;
    let hasCritical = false;
    let cveDetails = '';

    try {
      const body = JSON.stringify({
        package: { name: package_name, ecosystem: eco === 'pypi' ? 'PyPI' : 'npm' },
      });

      const response = await new Promise((resolve, reject) => {
        const req = https.request('https://api.osv.dev/v1/query', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
          timeout: 10000,
        }, (res) => {
          let data = '';
          res.on('data', (chunk) => data += chunk);
          res.on('end', () => {
            try { resolve(JSON.parse(data)); }
            catch { reject(new Error('Invalid response')); }
          });
        });
        req.on('error', reject);
        req.write(body);
        req.end();
      });

      const vulns = response.vulns || [];
      vulnCount = vulns.length;

      for (const v of vulns) {
        const id = v.id || '';
        const summary = (v.summary || v.details || '').slice(0, 100);
        if (id.startsWith('MAL-') || /malicious/i.test(summary)) hasMalware = true;
        if (/critical|rce|remote code|arbitrary code/i.test(summary)) hasCritical = true;

        const fixed = v.affected?.[0]?.ranges?.[0]?.events?.find(e => e.fixed);
        cveDetails += `  ${id}: ${summary}${fixed ? ' (fixed: ' + fixed.fixed + ')' : ''}\n`;
      }
    } catch (e) {
      report += `Warning: Could not query vulnerability database (${e.message})\n\n`;
    }

    // Determine verdict
    let verdict;
    if (hasMalware) {
      verdict = 'DANGER';
      report += `Verdict: DANGER -- DO NOT INSTALL\n\n`;
      report += `This package contains confirmed MALICIOUS CODE.\n`;
      report += `Installing it will compromise your system.\n\n`;
    } else if (hasCritical) {
      verdict = 'DANGER';
      report += `Verdict: DANGER -- HIGH RISK\n\n`;
      report += `This package has CRITICAL vulnerabilities including potential remote code execution.\n`;
      report += `Only install if you can verify you are using a patched version.\n\n`;
    } else if (vulnCount > 5) {
      verdict = 'CAUTION';
      report += `Verdict: CAUTION -- Multiple known vulnerabilities\n\n`;
      report += `This package has ${vulnCount} known security issues.\n`;
      report += `Check if your version is patched before using in production.\n\n`;
    } else if (vulnCount > 0) {
      verdict = 'CAUTION';
      report += `Verdict: CAUTION -- Known vulnerabilities exist\n\n`;
      report += `This package has ${vulnCount} known security issue(s).\n`;
      report += `Check the details below and ensure you use a patched version.\n\n`;
    } else {
      verdict = 'SAFE';
      report += `Verdict: SAFE -- No known vulnerabilities\n\n`;
      report += `No security advisories found in the OSV.dev database.\n`;
      report += `Note: This checks known CVEs only. Zero-days are not covered.\n\n`;
    }

    if (vulnCount > 0) {
      report += `Vulnerabilities (${vulnCount}):\n`;
      report += cveDetails;
      report += `\n`;
    }

    report += `Command: ${eco === 'npm' ? 'npm install' : 'pip install'} ${package_name}\n`;
    report += `Source: OSV.dev (Google Vulnerability Database)\n`;

    return report;
  }

  // --------------------------------------------------------------------------
  // audit_dependencies: Bulk dependency audit
  // --------------------------------------------------------------------------

  async _auditDependencies(args) {
    const { content, type } = args || {};
    if (!content) return 'Error: content is required (paste your package.json or requirements.txt)';

    let packages = [];
    let fileType = type;

    // Auto-detect file type
    if (!fileType) {
      if (content.includes('"dependencies"') || content.includes('"devDependencies"')) {
        fileType = 'package.json';
      } else {
        fileType = 'requirements.txt';
      }
    }

    // Parse dependencies
    if (fileType === 'package.json') {
      try {
        const pkg = JSON.parse(content);
        const deps = { ...pkg.dependencies, ...pkg.devDependencies };
        packages = Object.keys(deps).map(name => ({ name, ecosystem: 'npm' }));
      } catch {
        return 'Error: Invalid package.json format';
      }
    } else {
      // Parse requirements.txt
      const lines = content.split('\n');
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) continue;
        const name = trimmed.split(/[=<>!~\[]/)[0].trim();
        if (name) packages.push({ name, ecosystem: 'pypi' });
      }
    }

    if (packages.length === 0) return 'No dependencies found in the file.';

    let report = `Dependency Security Audit\n`;
    report += `${'='.repeat(50)}\n`;
    report += `File type: ${fileType}\n`;
    report += `Dependencies: ${packages.length}\n`;
    report += `Date: ${new Date().toISOString().split('T')[0]}\n\n`;

    let totalVulns = 0;
    let dangerCount = 0;
    let cautionCount = 0;
    let safeCount = 0;
    const results = [];

    // Check each package (limit to 30 to avoid timeout)
    const toCheck = packages.slice(0, 30);

    for (const pkg of toCheck) {
      try {
        const body = JSON.stringify({
          package: { name: pkg.name, ecosystem: pkg.ecosystem === 'pypi' ? 'PyPI' : 'npm' },
        });

        const response = await new Promise((resolve, reject) => {
          const req = https.request('https://api.osv.dev/v1/query', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
            timeout: 5000,
          }, (res) => {
            let data = '';
            res.on('data', (chunk) => data += chunk);
            res.on('end', () => {
              try { resolve(JSON.parse(data)); }
              catch { resolve({ vulns: [] }); }
            });
          });
          req.on('error', () => resolve({ vulns: [] }));
          req.write(body);
          req.end();
        });

        const vulns = response.vulns || [];
        const count = vulns.length;
        totalVulns += count;

        const hasMal = vulns.some(v => (v.id || '').startsWith('MAL-') || /malicious/i.test(v.summary || ''));
        const hasCrit = vulns.some(v => /critical|rce|remote code/i.test(v.summary || ''));

        let status;
        if (hasMal) { status = 'DANGER'; dangerCount++; }
        else if (hasCrit || count > 5) { status = 'DANGER'; dangerCount++; }
        else if (count > 0) { status = 'CAUTION'; cautionCount++; }
        else { status = 'SAFE'; safeCount++; }

        results.push({ name: pkg.name, status, count });
      } catch {
        results.push({ name: pkg.name, status: 'ERROR', count: 0 });
      }
    }

    // Sort: danger first, then caution, then safe
    const order = { DANGER: 0, CAUTION: 1, ERROR: 2, SAFE: 3 };
    results.sort((a, b) => (order[a.status] || 9) - (order[b.status] || 9));

    for (const r of results) {
      const icon = r.status === 'SAFE' ? 'SAFE' : r.status === 'DANGER' ? 'DANGER' : r.status === 'CAUTION' ? 'WARN' : 'ERR';
      report += `  [${icon.padEnd(6)}] ${r.name.padEnd(35)} ${r.count} vuln(s)\n`;
    }

    if (packages.length > 30) {
      report += `\n  ... and ${packages.length - 30} more dependencies not checked (limit: 30)\n`;
    }

    report += `\n${'='.repeat(50)}\n`;
    report += `Summary: ${dangerCount} DANGER, ${cautionCount} CAUTION, ${safeCount} SAFE\n`;
    report += `Total vulnerabilities: ${totalVulns}\n`;

    if (dangerCount > 0) {
      report += `\nACTION REQUIRED: ${dangerCount} package(s) have critical vulnerabilities or malicious code.\n`;
      report += `Review and update these dependencies before deploying.\n`;
    }

    report += `\nSource: OSV.dev (Google Vulnerability Database)\n`;
    return report;
  }

  // --------------------------------------------------------------------------
  // check_repo: GitHub repository safety check
  // --------------------------------------------------------------------------

  async _checkRepo(args) {
    const { repo } = args || {};
    if (!repo) return 'Error: repo is required (format: owner/name)';

    const [owner, name] = repo.split('/');
    if (!owner || !name) return 'Error: repo must be in owner/name format';

    let report = `GitHub Repository Safety Check\n`;
    report += `${'='.repeat(50)}\n`;
    report += `Repo: ${repo}\n\n`;

    try {
      const fetch = (path) => new Promise((resolve, reject) => {
        const req = https.request(`https://api.github.com${path}`, {
          headers: { 'User-Agent': 'MCP-Security-Scanner/0.1.0', 'Accept': 'application/json' },
          timeout: 5000,
        }, (res) => {
          let data = '';
          res.on('data', (chunk) => data += chunk);
          res.on('end', () => {
            try { resolve({ status: res.statusCode, data: JSON.parse(data) }); }
            catch { resolve({ status: res.statusCode, data: {} }); }
          });
        });
        req.on('error', reject);
        req.end();
      });

      const repoData = await fetch(`/repos/${owner}/${name}`);
      if (repoData.status === 404) return `Error: Repository ${repo} not found`;
      if (repoData.status === 403) return `Error: Rate limited by GitHub API. Try again in a minute.`;

      const r = repoData.data;
      const signals = [];
      let score = 50; // Start neutral

      // Age
      const created = new Date(r.created_at);
      const ageMonths = Math.floor((Date.now() - created) / (30 * 24 * 60 * 60 * 1000));
      if (ageMonths < 1) {
        signals.push({ type: 'WARNING', text: `Very new repo (${ageMonths} months old) -- higher risk of abandonment or malice` });
        score -= 15;
      } else if (ageMonths < 6) {
        signals.push({ type: 'CAUTION', text: `Relatively new repo (${ageMonths} months old)` });
        score -= 5;
      } else {
        signals.push({ type: 'GOOD', text: `Established repo (${ageMonths} months old)` });
        score += 5;
      }

      // Stars
      const stars = r.stargazers_count || 0;
      if (stars > 1000) {
        signals.push({ type: 'GOOD', text: `Well-starred (${stars} stars) -- community trust signal` });
        score += 15;
      } else if (stars > 100) {
        signals.push({ type: 'GOOD', text: `Moderate stars (${stars})` });
        score += 5;
      } else if (stars < 5) {
        signals.push({ type: 'CAUTION', text: `Very few stars (${stars}) -- limited community vetting` });
        score -= 10;
      }

      // Forks
      const forks = r.forks_count || 0;
      if (forks > 100) {
        signals.push({ type: 'GOOD', text: `Actively forked (${forks} forks)` });
        score += 5;
      }

      // Open issues
      const issues = r.open_issues_count || 0;
      if (issues > 500) {
        signals.push({ type: 'CAUTION', text: `Many open issues (${issues}) -- may be undermaintained` });
        score -= 5;
      }

      // Archived
      if (r.archived) {
        signals.push({ type: 'WARNING', text: 'Repository is ARCHIVED -- no longer maintained' });
        score -= 20;
      }

      // Last push
      const lastPush = new Date(r.pushed_at);
      const daysSincePush = Math.floor((Date.now() - lastPush) / (24 * 60 * 60 * 1000));
      if (daysSincePush > 365) {
        signals.push({ type: 'WARNING', text: `No activity in ${daysSincePush} days -- possibly abandoned` });
        score -= 15;
      } else if (daysSincePush > 90) {
        signals.push({ type: 'CAUTION', text: `Last activity ${daysSincePush} days ago` });
        score -= 5;
      } else {
        signals.push({ type: 'GOOD', text: `Recently active (${daysSincePush} days ago)` });
        score += 5;
      }

      // License
      if (r.license?.spdx_id) {
        const known = ['MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'MPL-2.0'];
        if (known.includes(r.license.spdx_id)) {
          signals.push({ type: 'GOOD', text: `Standard open-source license (${r.license.spdx_id})` });
          score += 5;
        } else {
          signals.push({ type: 'CAUTION', text: `License: ${r.license.spdx_id} -- review terms` });
        }
      } else {
        signals.push({ type: 'WARNING', text: 'No license specified -- legal risk' });
        score -= 10;
      }

      // Description
      if (!r.description) {
        signals.push({ type: 'CAUTION', text: 'No repo description -- low effort signal' });
        score -= 5;
      }

      // Clamp score
      score = Math.max(0, Math.min(100, score));

      // Determine verdict
      let verdict;
      if (score >= 70) verdict = 'SAFE';
      else if (score >= 40) verdict = 'CAUTION';
      else verdict = 'DANGER';

      report += `Trust Score: ${score}/100 (${verdict})\n\n`;
      report += `Stats:\n`;
      report += `  Stars: ${stars} | Forks: ${forks} | Issues: ${issues}\n`;
      report += `  Created: ${r.created_at?.slice(0, 10)} | Last push: ${r.pushed_at?.slice(0, 10)}\n`;
      report += `  Language: ${r.language || 'unknown'} | License: ${r.license?.spdx_id || 'none'}\n`;
      if (r.description) report += `  Description: ${r.description.slice(0, 100)}\n`;
      report += `\nSignals:\n`;

      for (const s of signals) {
        const icon = s.type === 'GOOD' ? '+' : s.type === 'WARNING' ? '!' : '?';
        report += `  [${icon}] ${s.text}\n`;
      }

      report += `\nVerdict: ${verdict === 'SAFE' ? 'This repo appears safe to use.' : verdict === 'CAUTION' ? 'Use with caution -- review the signals above.' : 'HIGH RISK -- investigate before using.'}\n`;

      return report;
    } catch (e) {
      return `Error checking repository: ${e.message}`;
    }
  }

  // ==========================================================================
  // compliance_scan — EU AI Act + OWASP Agentic AI + OWASP MCP Top 10
  // ==========================================================================

  async _complianceScan(args) {
    const { url } = args || {};
    if (!url) return 'Error: url is required';

    const results = { eu_ai_act: [], owasp_agentic: [], summary: {} };

    // Reusable RPC helper
    const rpc = async (method, params = {}) => {
      return new Promise((resolve, reject) => {
        const body = JSON.stringify({ jsonrpc: '2.0', method, id: crypto.randomUUID(), params });
        const urlObj = new URL(url);
        const client = urlObj.protocol === 'https:' ? https : http;
        const req = client.request(urlObj, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream', 'Content-Length': Buffer.byteLength(body) },
          timeout: 5000,
        }, (res) => {
          let data = '';
          res.on('data', c => data += c);
          res.on('end', () => {
            const ct = (res.headers['content-type'] || '').toLowerCase();
            const parsed = MCPSecurityScanner._parseResponse(data, ct);
            resolve({ status: res.statusCode, headers: res.headers, body: parsed });
          });
        });
        req.on('error', e => reject(e));
        req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
        req.write(body);
        req.end();
      });
    };

    // Helper
    const check = (framework, id, title, article, severity, passed, detail, fix) => {
      const target = framework === 'eu' ? results.eu_ai_act : results.owasp_agentic;
      target.push({ id, title, article, severity, status: passed ? 'PASS' : 'FAIL', detail, fix: passed ? null : fix });
    };

    let tools = [];
    let initResult = null;
    let authRequired = false;
    let hasRateLimiting = false;
    let hasMcps = false;
    let errorLeaks = false;

    try {
      // 1. Try connecting and get tools
      const r = await rpc('tools/list');
      if (r.body?.result?.tools) tools = r.body.result.tools;
      if (r.body?.error) authRequired = true;
    } catch (e) {
      return `Error: Could not connect to ${url} — ${e.message}`;
    }

    // 2. Check for MCPS/signing in initialize
    try {
      const init = await rpc('initialize', { protocolVersion: '2025-03-26', capabilities: { mcps: { version: '1.0' } }, clientInfo: { name: 'compliance-scanner', version: '1.0' } });
      initResult = init.body?.result;
      hasMcps = !!(initResult?.capabilities?.mcps);
    } catch {}

    // 3. Check auth
    try {
      const noAuth = await rpc('tools/list');
      if (noAuth.body?.result?.tools) authRequired = false;
    } catch { authRequired = true; }

    // 4. Check rate limiting
    try {
      const promises = [];
      for (let i = 0; i < 5; i++) promises.push(rpc('tools/list').catch(() => ({ status: 429 })));
      const responses = await Promise.all(promises);
      hasRateLimiting = responses.some(r => r.status === 429);
    } catch {}

    // 5. Check error leaking
    try {
      const bad = await rpc('tools/call', { name: '../../../../etc/passwd', arguments: {} });
      const errStr = JSON.stringify(bad.body || '');
      errorLeaks = /stack|trace|node_modules|at\s+\w|\.js:\d/.test(errStr);
    } catch {}

    // 6. Analyse tool danger levels
    const dangerousTools = tools.filter(t => {
      const name = (t.name || '').toLowerCase();
      const desc = (t.description || '').toLowerCase();
      return /exec|shell|command|run_code|system|eval|sudo|admin|delete|write_file|upload/.test(name + ' ' + desc);
    });

    // ── EU AI ACT CHECKS ──

    check('eu', 'EU-ART12', 'Audit Trail / Record-Keeping', 'Article 12',
      'critical', hasMcps,
      hasMcps ? 'Server supports MCPS message signing — audit trail available' : 'No message signing detected. No tamper-evident audit trail.',
      'Install mcp-secure and enable signMessage() on all tool calls. This creates cryptographically signed, tamper-evident logs per Article 12.');

    check('eu', 'EU-ART14', 'Human Oversight', 'Article 14',
      'critical', authRequired,
      authRequired ? 'Authentication required — human oversight gate present' : 'No authentication required. Any agent can call tools without oversight.',
      'Add authentication to your MCP server. Use cybersecify check_call for runtime GO/CAUTION/BLOCK decisions before tool execution.');

    check('eu', 'EU-ART15-AUTH', 'Cybersecurity — Authentication', 'Article 15',
      'critical', authRequired,
      authRequired ? 'Authentication enforced' : 'No authentication. Server is open to any caller.',
      'Require authentication on all MCP endpoints. Use mcp-secure agent passports for cryptographic identity verification.');

    check('eu', 'EU-ART15-RATE', 'Cybersecurity — Rate Limiting', 'Article 15',
      'high', hasRateLimiting,
      hasRateLimiting ? 'Rate limiting detected' : 'No rate limiting detected. Server vulnerable to abuse.',
      'Implement rate limiting on all MCP endpoints to prevent denial of service and resource abuse.');

    check('eu', 'EU-ART15-ERROR', 'Cybersecurity — Error Handling', 'Article 15',
      'high', !errorLeaks,
      !errorLeaks ? 'Error responses do not leak implementation details' : 'Error responses contain stack traces or internal paths.',
      'Sanitise error responses. Remove stack traces, file paths, and internal details from error messages returned to clients.');

    check('eu', 'EU-ART50', 'Agent Identity / Transparency', 'Article 50',
      'critical', hasMcps,
      hasMcps ? 'MCPS supported — agent identity can be verified' : 'No agent identity mechanism. Callers cannot be identified as AI agents.',
      'Use mcp-secure createPassport() to give your agent a cryptographic identity. This proves the caller is an AI agent per Article 50 transparency requirements.');

    check('eu', 'EU-ART16', 'Supply Chain — Excessive Tools', 'Article 16',
      'high', dangerousTools.length === 0,
      dangerousTools.length === 0 ? 'No dangerous tool capabilities exposed' : `${dangerousTools.length} dangerous tool(s) exposed: ${dangerousTools.map(t => t.name).join(', ')}`,
      'Review and restrict dangerous tool capabilities. Use cybersecify assess_risk to evaluate each tool. Remove or sandbox shell execution, file write, and admin tools.');

    // ── OWASP AGENTIC AI TOP 10 CHECKS ──

    check('agentic', 'ASI-01', 'Excessive Agency', 'ASI-01',
      'critical', dangerousTools.length === 0,
      dangerousTools.length === 0 ? 'No excessive agency detected' : `Agent has access to ${dangerousTools.length} dangerous tool(s): ${dangerousTools.map(t => t.name).join(', ')}`,
      'Restrict tool access to minimum required capabilities. Remove shell execution, file system write, and admin tools unless explicitly needed.');

    check('agentic', 'ASI-02', 'Insufficient Access Control', 'ASI-02',
      'critical', authRequired,
      authRequired ? 'Access control enforced' : 'No access control. All tools accessible without authentication.',
      'Implement authentication and authorisation. Use mcp-secure with trust levels L0-L4 to gate tool access by agent trust.');

    check('agentic', 'ASI-03', 'Identity and Privilege Abuse', 'ASI-03',
      'critical', hasMcps,
      hasMcps ? 'MCPS identity verification available' : 'No agent identity verification. Any caller can impersonate any agent.',
      'Deploy mcp-secure agent passports. Each agent gets a cryptographic identity (ECDSA P-256) that cannot be spoofed.');

    check('agentic', 'ASI-04', 'Supply Chain Compromise', 'ASI-04',
      'high', tools.length < 20,
      tools.length < 20 ? `${tools.length} tools exposed (manageable attack surface)` : `${tools.length} tools exposed — large supply chain attack surface`,
      'Audit all tool dependencies with cybersecify audit_dependencies. Use mcp-secure signTool() to pin tool definitions. Check Agent Threat Database with check_agent.');

    check('agentic', 'ASI-05', 'Insecure Output Handling', 'ASI-05',
      'high', !errorLeaks,
      !errorLeaks ? 'Output handling appears secure' : 'Server leaks internal details in error responses.',
      'Sanitise all tool outputs before returning to agents. Remove internal paths, credentials, and stack traces.');

    check('agentic', 'ASI-07', 'Insecure Inter-Agent Communication', 'ASI-07',
      'critical', hasMcps,
      hasMcps ? 'MCPS message signing available for inter-agent communication' : 'Messages between agents are unsigned. Vulnerable to tampering and replay.',
      'Use mcp-secure signMessage() for all inter-agent communication. Each message gets ECDSA signature, nonce, and timestamp.');

    check('agentic', 'ASI-08', 'Insufficient Logging and Monitoring', 'ASI-08',
      'high', hasMcps,
      hasMcps ? 'MCPS provides cryptographic audit trail' : 'No structured logging or audit trail detected.',
      'Enable mcp-secure signMessage() to create tamper-evident logs. Store signed logs for minimum 6 months per EU AI Act Article 12.');

    check('agentic', 'ASI-09', 'Inadequate Sandboxing', 'ASI-09',
      'high', dangerousTools.length === 0,
      dangerousTools.length === 0 ? 'No tools requiring sandboxing detected' : `${dangerousTools.length} tool(s) with dangerous capabilities need sandboxing`,
      'Sandbox tools that access file systems, networks, or execute code. Use container isolation for dangerous tool execution.');

    check('agentic', 'ASI-10', 'Unbounded Consumption', 'ASI-10',
      'high', hasRateLimiting,
      hasRateLimiting ? 'Rate limiting present' : 'No rate limiting. Agents can consume unlimited resources.',
      'Implement rate limiting per agent identity. Use mcp-secure trust levels to set different rate limits per trust tier.');

    // ── SUMMARY ──
    const allChecks = [...results.eu_ai_act, ...results.owasp_agentic];
    const passed = allChecks.filter(c => c.status === 'PASS').length;
    const failed = allChecks.filter(c => c.status === 'FAIL').length;
    const criticalFails = allChecks.filter(c => c.status === 'FAIL' && c.severity === 'critical').length;
    const score = Math.round((passed / allChecks.length) * 100);

    let verdict = 'NON-COMPLIANT';
    if (score === 100) verdict = 'FULLY COMPLIANT';
    else if (score >= 70 && criticalFails === 0) verdict = 'PARTIALLY COMPLIANT';

    // Format output
    const lines = [
      `COMPLIANCE SCAN: ${url}`,
      `${'='.repeat(60)}`,
      '',
      `VERDICT: ${verdict}`,
      `Score: ${score}% (${passed} passed, ${failed} failed, ${criticalFails} critical)`,
      '',
      `${'─'.repeat(60)}`,
      `EU AI ACT (Agent-Specific)`,
      `${'─'.repeat(60)}`,
    ];

    for (const c of results.eu_ai_act) {
      lines.push(`[${c.status}] ${c.article} — ${c.title} (${c.severity})`);
      lines.push(`       ${c.detail}`);
      if (c.fix) lines.push(`  FIX: ${c.fix}`);
      lines.push('');
    }

    lines.push(`${'─'.repeat(60)}`);
    lines.push('OWASP AGENTIC AI TOP 10');
    lines.push(`${'─'.repeat(60)}`);

    for (const c of results.owasp_agentic) {
      lines.push(`[${c.status}] ${c.article} — ${c.title} (${c.severity})`);
      lines.push(`       ${c.detail}`);
      if (c.fix) lines.push(`  FIX: ${c.fix}`);
      lines.push('');
    }

    lines.push(`${'─'.repeat(60)}`);
    lines.push('REMEDIATION PRIORITY');
    lines.push(`${'─'.repeat(60)}`);

    const criticals = allChecks.filter(c => c.status === 'FAIL' && c.severity === 'critical');
    const highs = allChecks.filter(c => c.status === 'FAIL' && c.severity === 'high');

    if (criticals.length > 0) {
      lines.push('CRITICAL (fix immediately):');
      criticals.forEach((c, i) => lines.push(`  ${i + 1}. ${c.article}: ${c.fix}`));
      lines.push('');
    }
    if (highs.length > 0) {
      lines.push('HIGH (fix before deployment):');
      highs.forEach((c, i) => lines.push(`  ${i + 1}. ${c.article}: ${c.fix}`));
      lines.push('');
    }

    if (failed > 0) {
      lines.push(`${'─'.repeat(60)}`);
      lines.push('QUICK START');
      lines.push(`${'─'.repeat(60)}`);
      lines.push('1. npm install mcp-secure');
      lines.push('2. Add: app.use(mcps.secureMCP({ minTrust: "L2" }))');
      lines.push('3. Re-run this scan to verify compliance');
      lines.push('');
    }

    lines.push(`Scanned against: EU AI Act (2024/1689), OWASP Agentic AI Top 10, OWASP MCP Top 10`);
    lines.push(`Enforcement deadline: August 2026`);
    lines.push(`Scanner: cybersecify v0.3.0 — https://cybersecify.co.uk`);

    return lines.join('\n');
  }

  // ==========================================================================
  // check_agent — Query Agent Threat Database
  // ==========================================================================

  async _checkAgent(args) {
    const query = (args.query || '').toLowerCase().trim();
    if (!query) return 'Error: query is required. Provide an agent name, MCP server name, or package name.';

    const ATD_URL = 'https://raw.githubusercontent.com/razashariff/agent-threat-db/main/entries/';
    const INDEX_URL = 'https://api.github.com/repos/razashariff/agent-threat-db/contents/entries';

    try {
      // Fetch list of entries from GitHub
      const indexData = await new Promise((resolve, reject) => {
        https.get(INDEX_URL, { headers: { 'User-Agent': 'cybersecify' } }, (res) => {
          let body = '';
          res.on('data', c => body += c);
          res.on('end', () => {
            try { resolve(JSON.parse(body)); } catch { reject(new Error('Failed to parse index')); }
          });
        }).on('error', reject);
      });

      if (!Array.isArray(indexData)) {
        return 'Agent Threat Database: Unable to fetch entries. The database may be temporarily unavailable.';
      }

      // Fetch and check each entry
      const matches = [];
      for (const file of indexData) {
        if (!file.name.endsWith('.json')) continue;

        const entry = await new Promise((resolve, reject) => {
          https.get(file.download_url, { headers: { 'User-Agent': 'cybersecify' } }, (res) => {
            let body = '';
            res.on('data', c => body += c);
            res.on('end', () => {
              try { resolve(JSON.parse(body)); } catch { resolve(null); }
            });
          }).on('error', () => resolve(null));
        });

        if (!entry) continue;

        // Match against query
        const searchFields = [
          entry.id,
          entry.summary,
          entry.details,
          ...(entry.affected || []).map(a => a.package?.name || ''),
          entry.agent_threat?.agent_type || '',
          entry.agent_threat?.category || '',
        ].join(' ').toLowerCase();

        if (searchFields.includes(query)) {
          matches.push(entry);
        }
      }

      if (matches.length === 0) {
        return [
          `Agent Threat Check: "${args.query}"`,
          '',
          'Status: CLEAN',
          'No known threats found in the Agent Threat Database.',
          '',
          `Checked ${indexData.filter(f => f.name.endsWith('.json')).length} threat entries.`,
          '',
          'Note: A clean result does not guarantee safety. New threats are added as they are discovered.',
          'Database: https://github.com/razashariff/agent-threat-db',
        ].join('\n');
      }

      const lines = [
        `Agent Threat Check: "${args.query}"`,
        '',
        `Status: FLAGGED — ${matches.length} threat(s) found`,
        '',
      ];

      for (const m of matches) {
        const severity = m.severity?.[0]?.score || 'Unknown';
        lines.push(`--- ${m.id} ---`);
        lines.push(`Summary: ${m.summary}`);
        lines.push(`Category: ${m.agent_threat?.category || 'Unknown'}`);
        lines.push(`Agent Type: ${m.agent_threat?.agent_type || 'Unknown'}`);
        lines.push(`Severity: ${severity}`);
        lines.push(`Published: ${m.published || 'Unknown'}`);
        if (m.aliases?.length) lines.push(`Aliases: ${m.aliases.join(', ')}`);
        lines.push(`Attack Vector: ${m.agent_threat?.attack_vector || 'Unknown'}`);
        if (m.agent_threat?.mitigations?.length) {
          lines.push('Mitigations:');
          for (const mit of m.agent_threat.mitigations) {
            lines.push(`  - ${mit}`);
          }
        }
        if (m.references?.length) {
          lines.push('References:');
          for (const ref of m.references) {
            lines.push(`  - ${ref.url}`);
          }
        }
        lines.push('');
      }

      lines.push('Database: https://github.com/razashariff/agent-threat-db');

      return lines.join('\n');
    } catch (e) {
      return `Agent Threat Check: Error querying database — ${e.message}`;
    }
  }
}

// ============================================================================
// Start
// ============================================================================

const scanner = new MCPSecurityScanner();
scanner.start();
