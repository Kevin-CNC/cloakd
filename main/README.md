# Cloakd

<div align="center">  
  <b>Anonymize sensitive data before it reaches language models.</b>
</div>

---

## Table of Contents

| Section | Purpose |
|---------|---------|
| [Overview](#overview) | What Cloakd does |
| [Features](#features) | Key capabilities |
| [Getting Started](#getting-started) | Quick setup guide |
| [Configuration](#configuration) | Settings reference |
| [Architecture](#architecture) | How it works |
| [License](#license) | Licensing information |

---

## Overview

Cloakd is a VS Code extension that automatically anonymizes sensitive values before they're sent to language models. It maintains a strict privacy boundary: secrets are anonymized before reaching the LM, de-anonymized only in local tool implementations, and re-anonymized before returning results.

**What it solves:**
- API keys, passwords, and credentials sent to language models
- Infrastructure details exposed in prompts and responses
- De-anonymization leaking secrets back to external systems
- Manual tracking of sensitive information across prompts

---

## Features

**Anonymous Pattern Matching** — Regex-based patterns with built-in support for IPs, emails, UUIDs, API keys, JWT tokens, and private keys.

**Rule Editor** — Vue.js interface for managing anonymization rules in per-workspace `.cloakd/` files.

**IaC Scanner** — Detects Terraform secrets (AWS account IDs, ARNs, CIDR blocks, credentials) and suggests rules.

**Token Consistency** — Maps secrets to stable tokens (e.g., `IP_1`, `API_KEY_2`) for reliable LM interaction.

**LM Tool Integration** — Three tools with full anonymization: command execution, SCP transfers, and filesystem operations.

**@Cloakd Chat Participant** — Built-in VS Code Chat integration with automatic anonymization.

---

## Technology Stack

TypeScript • VS Code Extension API • Vue.js 3 • Tailwind CSS • Vite • Webpack • JSON

---

## Commands

- `cloakd.activate` — Activate extension with ruleset selection
- `cloakd.openUI` — Open main rule editor panel
- `cloakd.openRuleEditor` — Open sidebar rule editor
- `cloakd.showMappings` — Display current token mappings
- `cloakd.clearMappings` — Clear all token mappings
- `cloakd.scanIacFile` — Scan file for detectable secrets
- `cloakd.switchRulesheet` — Switch active ruleset
- `cloakd.quickAddRule` — Add a rule from command palette

---

## Getting Started

**Installation:**
1. Open VS Code Extensions (Ctrl+Shift+X)
2. Search for "Cloakd" and install

**Setup:**
1. Run command: `Cloakd: Open UI`
2. Create a new ruleset (e.g., `my-project`)
3. Add rules manually or use the IaC scanner to detect secrets
4. In VS Code Chat, use `@Cloakd` to anonymize your prompts

**Example rule:**
```json
{
  "id": "rule-1",
  "type": "ip",
  "pattern": "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b",
  "replacement": "IP",
  "enabled": true
}
```

---

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `cloakd.agent.maxToolRounds` | `10` | Max tool execution rounds |
| `cloakd.agent.executionMode` | `captured` | Tool mode: `captured` or `terminal` |
| `cloakd.agent.toolScope` | `all` | Available tools: `cloakdOnly` or `all` |
| `cloakd.mappings.autoClearOnSessionStart` | `false` | Clear mappings on new session |
| `cloakd.mappings.autoClearOnRulesheetSwitch` | `false` | Clear mappings on ruleset switch |
| `cloakd.logging.level` | `info` | Log level: `debug`, `info`, `warn`, `error` |

---

## Architecture

**Anonymization Engine** — Loads enabled rules, compiles regex patterns (longest-first), finds non-overlapping matches, generates consistent tokens, and replaces in reverse order.

**Token Manager** — Maintains mappings between original values and tokens, persisted in VS Code's `workspaceState`.

**IaC Scanner** — Detects Terraform-specific secrets or uses generic fallback patterns.

**LM Tools** — Three tools with full de/re-anonymization:
- `cloakd_execute_command` — Run shell commands safely
- `cloakd_scp_transfer` — Secure file transfers
- `cloakd_filesystem` — File read/write/patch/delete operations

**Privacy Boundary:**
1. Input anonymized before reaching the LM
2. De-anonymized only in local tool code
3. Tool outputs re-anonymized before returning to model

---

## License

Kept under MIT licence as of 08/02/2026 (dd/mm/yy).

---

## Support

Questions or issues? Open a GitHub issue in the project repository.
