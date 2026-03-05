# sigil

Deep static security analysis for MCP servers. Finds command injection, path traversal, tool poisoning, credential leaks, and 12 other vulnerability classes — source code analysis that goes beyond description scanning.

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![npm version](https://img.shields.io/npm/v/@sigildev/sigil.svg)](https://www.npmjs.com/package/@sigildev/sigil)

---

## The Problem

MCP servers are the bridge between AI agents and the real world — file systems, databases, APIs, shell commands. They're also largely unaudited. Studies of MCP implementations found **43% vulnerable to command injection**, **82% using file operations prone to path traversal**, and **5.5% with active tool poisoning** in their descriptions. Existing scanners check tool descriptions and metadata. They don't read the source code. sigil does.

## What sigil Does

- **Source code analysis** — Reads TypeScript and Python source, detects dangerous patterns in tool handlers (exec, eval, fs, SQL), flags unsanitized paths. Goes beyond description scanning — analyzes what your code actually does.
- **16 security rules across 7 categories** — Injection, permissions, data exfiltration, input validation, tool description integrity, authentication, configuration. Each rule maps to documented MCP attack vectors and real CVEs.
- **Trust score (0-100)** — Quantified security posture with A-F grading. Exit code 1 on FAIL for CI/CD gating. One critical finding = 75 or below.

## Quick Start

```bash
npx @sigildev/sigil .
```

```
  Sigil v0.1.0

  Scanning: ./my-mcp-server
  Language: TypeScript
  Tools: 5 detected | Resources: 2 detected | Prompts: 0 detected

  CRITICAL  MCS-INJ-001  Command Injection via tool input
  │ src/tools/run-command.ts:24
  │ Tool "execute" passes user input directly to child_process.exec()
  │ without sanitization. Allows arbitrary command execution.
  │
  │   23│ server.tool("execute", { cmd: z.string() }, async ({ cmd }) => {
  │ > 24│   const result = await exec(cmd);
  │   25│   return { content: [{ type: "text", text: result.stdout }] };

  HIGH  MCS-PERM-002  Unrestricted filesystem access
  │ src/tools/files.ts:12
  │ Tool "read_file" accepts arbitrary paths with no allowlist or
  │ directory restriction. Can read /etc/passwd, SSH keys, .env files.

  HIGH  MCS-DATA-001  Environment variable exposure
  │ src/tools/debug.ts:8
  │ Tool "get_env" returns process.env without filtering.
  │ Exposes API keys, credentials, and secrets to the LLM.

  MEDIUM  MCS-VALID-001  Missing input schema
  │ src/tools/search.ts:31
  │ Tool "search" has no input validation schema defined.
  │ All inputs accepted without type or constraint checking.

  LOW  MCS-CFG-002  Verbose error messages
  │ src/index.ts:45
  │ Error handler returns full stack traces to the client.

  ──────────────────────────────────────────────────────
  5 findings: 1 critical, 2 high, 1 medium, 1 low
  Trust Score: 32/100 (FAIL)
  ──────────────────────────────────────────────────────
```

## Installation

```bash
# Run without installing
npx @sigildev/sigil .

# Install globally
npm install -g @sigildev/sigil

# Install as dev dependency
npm install -D @sigildev/sigil
```

## Usage

```bash
# Scan an MCP server directory
sigil .
sigil ./servers/github-server

# Scan all servers in a config file
sigil claude_desktop_config.json
sigil .mcp.json

# Machine-readable output
sigil . --output json
sigil . --output sarif

# Filter by severity
sigil . -s high          # Only high and critical findings

# Ignore specific rules
sigil . --ignore MCS-CFG-002,MCS-DEP-002

# Quiet mode (findings only, no banner)
sigil . -q
```

## What It Checks

16 rules across 7 categories. Each maps to real MCP attack vectors and documented CVEs.

| ID | Rule | Severity | What it detects |
|----|------|----------|-----------------|
| MCS-INJ-001 | Command Injection | CRITICAL | Tool inputs passed to `exec`, `spawn(shell)`, `os.system`, `subprocess.run(shell=True)` |
| MCS-INJ-002 | SQL Injection | CRITICAL | Tool inputs concatenated into SQL strings without parameterized queries |
| MCS-INJ-003 | Path Traversal | HIGH | Tool inputs used in file paths without canonicalization or directory restriction |
| MCS-PERM-001 | Overly Broad Capabilities | HIGH | Tools performing dangerous ops (write, delete, fetch, exec) without scope restrictions |
| MCS-PERM-002 | Unrestricted FS Access | HIGH | File system tools with no directory allowlist or path prefix restriction |
| MCS-PERM-003 | Arbitrary Code Execution | CRITICAL | Tool inputs passed to `eval()`, `Function()`, `exec()`, `vm.runInNewContext` |
| MCS-DATA-001 | Env Variable Exposure | HIGH | `process.env` or `os.environ` returned wholesale without filtering |
| MCS-DATA-002 | Credential Leakage | HIGH | Unfiltered API responses containing auth tokens, session IDs, or credentials |
| MCS-VALID-001 | Missing Input Schema | MEDIUM | Tools registered with empty or absent input validation schemas |
| MCS-DESC-001 | Suspicious Descriptions | HIGH | Prompt injection patterns in tool descriptions (override instructions, exfiltration URLs, cross-tool calls) |
| MCS-AUTH-001 | Hardcoded Credentials | CRITICAL | API keys, tokens, passwords hardcoded in source (`sk-*`, `ghp_*`, `AKIA*`, private keys) |
| MCS-AUTH-002 | Secrets in Config | HIGH | Credentials inline in MCP config files instead of env var references |
| MCS-CFG-001 | Debug Mode Enabled | MEDIUM | Debug/development configuration left enabled |
| MCS-CFG-002 | Verbose Error Messages | LOW | Error handlers returning full stack traces to the client |
| MCS-CFG-003 | Insecure Transport | MEDIUM | HTTP without TLS, binding to `0.0.0.0`, CORS with `*` |
| MCS-DEP-001 | Vulnerable Dependencies | Varies | Dependencies with known CVEs (queried against OSV.dev) |

## Output Formats

### Text (default)

Human-readable terminal output with color-coded severity badges and inline code excerpts. See Quick Start above.

### JSON

```bash
sigil . --output json
```

Produces a structured `ScanResult` object with full finding details, tool/resource/prompt inventory, and trust score. Pipe to `jq` or consume programmatically.

### SARIF

```bash
sigil . --output sarif
```

SARIF v2.1.0 output for integration with GitHub Code Scanning, VS Code SARIF Viewer, and other SARIF-compatible tools. Upload directly to GitHub:

```bash
sigil . --output sarif > results.sarif
# Upload to GitHub Code Scanning via API or Action
```

## Trust Score

```
Score = 100 - penalties

CRITICAL  = -25 points each
HIGH      = -15 points each
MEDIUM    = -5 points each
LOW       = -2 points each

A (90-100) = PASS    D (30-49) = FAIL
B (70-89)  = PASS    F (0-29)  = FAIL
C (50-69)  = WARN
```

Exit code `0` on PASS (score >= 70). Exit code `1` on FAIL. Use in CI/CD to block deployments.

## Configuration

Create `.sigil.yml` in your project root:

```yaml
# Rules to ignore
ignore:
  - MCS-CFG-002    # We intentionally show verbose errors in dev
  - MCS-DEP-002    # We know this server is maintained

# Severity overrides
overrides:
  MCS-VALID-001: low    # Downgrade missing schema for our use case

# Paths to exclude
exclude:
  - "tests/**"
  - "examples/**"
  - "**/*.test.ts"

# Minimum score to pass (default: 70)
passScore: 60
```

## How It Works

Three-layer analysis pipeline. No dynamic analysis — the scanner never runs your MCP server.

1. **Discovery** — Finds MCP server entry points, parses config files (`claude_desktop_config.json`, `.mcp.json`), reads `package.json`/`pyproject.toml`, discovers source files.
2. **Analysis** — 16 rules run against source code:
   - **Pattern Analyzer** — Context-aware regex detection for injection sinks, dangerous permissions, credential leaks, prompt injection, and configuration issues. Checks surrounding code context to reduce false positives.
   - **Dependency Checker** — Parses dependency manifests, queries OSV.dev for known CVEs.
3. **Reporting** — Aggregates findings, computes trust score, formats output.

## Comparison

| Feature | sigil | Snyk agent-scan | Cisco Sigil | Enkrypt AI |
|---------|-------------|-----------------|-------------------|------------|
| Open source | MIT | Partial | Partial | No |
| Analysis depth | Source code pattern analysis | Description scanning | YARA rules + LLM | Agentic static |
| Languages | TypeScript + Python | Runtime only | Unknown | GitHub repos |
| Trust scoring | 0-100 + A-F grade | Pass/fail | None | Per-finding |
| SARIF output | Yes | No | No | No |
| Config scanning | Yes | No | No | No |
| Dependency scanning | Yes (OSV.dev) | No | No | No |
| Description poisoning | Yes | Yes | Yes (LLM) | Yes |
| Cost | Free | Free (scanner), paid (platform) | Free (scanner), paid (API) | Free tier, paid |

**Our edge:** Deep source code analysis (not just description scanning), both TypeScript and Python, trust scoring, config file scanning, dependency checking, and SARIF output — in a single free, open-source CLI. No account required. No data sent to external services (except OSV.dev for dependency CVE checks).

## Supported MCP Frameworks

- `@modelcontextprotocol/sdk` (TypeScript) — `server.tool()`, `server.resource()`, `server.prompt()`
- `mcp` / FastMCP (Python) — `@mcp.tool()`, `@mcp.resource()`, `@mcp.prompt()`

## Contributing

Contributions welcome. Areas where help is needed:

- **New rules** — See the rule template in `src/rules/`. Each rule is a self-contained module.
- **Language support** — Go, Rust, Java MCP server analysis.
- **False positive reports** — If the scanner flags safe code, open an issue with a minimal repro.
- **Real-world validation** — Run the scanner on your MCP servers and share results (with permission).

```bash
git clone https://github.com/sigildev/sigil
cd sigil
npm install
npm test
npm run dev -- ./tests/fixtures/vulnerable-ts
```

## License

MIT
