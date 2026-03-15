# Cloakd

<div align="center">
  <b>Anonymize sensitive data before it reaches language models.</b>
</div>

---

## Table of Contents

| Section | Purpose |
|---------|---------|
| [What Cloakd Does](#what-cloakd-does) | Beginner overview |
| [How It Works](#how-it-works) | Privacy model in plain language |
| [Newest Features](#newest-features) | Recent capabilities and UI updates |
| [Quick Start for Beginners](#quick-start-for-beginners) | First successful setup |
| [Daily Workflows](#daily-workflows) | Common tasks with examples |
| [Wrapped Tool Trust Policy](#wrapped-tool-trust-policy) | Safe use of non-Cloakd tools |
| [Commands and Shortcuts](#commands-and-shortcuts) | Full command list |
| [Configuration](#configuration) | Important settings and defaults |
| [Limitations](#limitations) | Current boundaries |
| [Troubleshooting](#troubleshooting) | Fix common setup issues |

---

## What Cloakd Does

Cloakd is a VS Code extension that helps you use AI tools without exposing raw secrets.

It replaces sensitive values (for example API keys, hostnames, IPs, emails, paths, tokens) with anonymized placeholders before data reaches the model.

Example:

- Original: `Deploy to 10.4.1.25 with key sk_live_ABC123`
- Sent to model: `Deploy to IP_1 with key API_KEY_1`

This keeps model-visible text safer while preserving enough context for useful AI help.

---

## How It Works

Cloakd follows a strict boundary:

1. Anonymize before model access.
2. De-anonymize only inside trusted local tool execution paths.
3. Re-anonymize tool outputs before returning text to model-visible flows.

In practice, you keep working normally while Cloakd handles token mapping and privacy controls in the background.

---

## Newest Features

### 1) Dynamic Wrapped Tools (feature flag)

Cloakd can now expose wrapped aliases for non-native tools.

- Alias pattern: `cloakd_wrap_<toolName>`
- Default policy: `tokenOnly` (safe default)
- Optional policies: selective or trusted de-anonymization

### 2) Wrapped Tool Trust Policy panel

The main UI now includes a dedicated section for wrapped-tool trust configuration.

- Enable or disable dynamic wrapping
- Select mode (`strict`, `balanced`, `trustedLocal`)
- Edit optional JSON overrides

### 3) Cleaner UI structure

Main UI is split into separate submenus to reduce clutter:

- `Rule Addition`
- `Wrapped Tool Trust Policy`

### 4) Safer settings persistence

Dynamic wrapping settings are now written using supported configuration scope behavior, reducing settings-write errors in multi-folder contexts.

---

## Quick Start for Beginners

### Step 1: Install and open Cloakd

1. Install the extension.
2. Run `Cloakd: Open Main UI`.

### Step 2: Create your first rulesheet

1. Run `Cloakd: Create Rulesheet`.
2. Choose your workspace folder.
3. Create a `.cloakd/<name>.cloakd.json` rulesheet.

### Step 3: Add a simple rule

Use `Rule Addition` in the main UI, or highlight text and run `Cloakd: Quick Add Rule`.

Example rule:

```json
{
  "id": "rule-1",
  "type": "ip",
  "pattern": "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b",
  "replacement": "IP",
  "enabled": true
}
```

### Step 4: Use Cloakd in chat

In VS Code Chat, explicitly use `@Cloakd`.

Important: Cloakd protection is designed for the `@Cloakd` participant flow.

---

## Daily Workflows

### Workflow A: Ask AI about logs safely

1. Paste log snippets in `@Cloakd` chat.
2. Cloakd anonymizes matching sensitive values.
3. Model responds using tokenized placeholders.

### Workflow B: Scan files and generate rules

1. Run `Cloakd: Scan Current File for Secrets` or `Cloakd: Scan File for Secrets`.
2. Review detected items in UI.
3. Save selected rules.

### Workflow C: Use local tools through Cloakd

With `@Cloakd`, model can use:

- `cloakd_execute_command`
- `cloakd_scp_transfer`
- `cloakd_filesystem`

These tools preserve Cloakd privacy boundaries during invocation and result handling.

---

## Wrapped Tool Trust Policy

Use this only when you need non-native or third-party tools in the loop.

### Modes

- `strict`: safest default behavior
- `balanced`: still conservative, tuned for practicality
- `trustedLocal`: allows more de-anonymization flexibility for trusted local use

### Recommended rollout

1. Start with `enabled = false`.
2. Enable dynamic wrapping only when needed.
3. Keep mode as `strict` first.
4. Add per-tool overrides only after validating behavior.

### Optional policy override example

`Policy Overrides JSON` is the advanced control surface for wrapped tools.

What it does:

- Defines a default trust policy for all wrapped tools via `defaultPolicy`.
- Applies targeted exceptions for specific tools via `perTool`.
- Controls de-anonymization behavior (`tokenOnly`, `selectiveDeanonymize`, `trusted`).
- Restricts selective de-anonymization to explicit input paths.
- Enforces input/output size limits to reduce risk and noisy output.

What it achieves for developers:

- Lets custom tools work without weakening privacy for every tool.
- Supports principle-of-least-privilege for tool input exposure.
- Makes trust behavior explicit, reviewable, and team-shareable in workspace settings.

How to use it safely:

1. Keep `defaultPolicy` conservative (`tokenOnly`, `allowExternal: false`).
2. Add per-tool overrides only for tools that fail under strict policy.
3. Prefer `selectiveDeanonymize` with narrow `allowedInputPaths`.
4. Use `trusted` only for fully trusted local workflows.

```json
{
  "defaultPolicy": {
    "mode": "tokenOnly",
    "allowExternal": false,
    "maxInputSize": 100000,
    "maxOutputSize": 150000
  },
  "perTool": {
    "exampleTrustedTool": {
      "mode": "selectiveDeanonymize",
      "allowExternal": true,
      "allowedInputPaths": ["credentials.password"]
    }
  }
}
```

Field reference:

- `mode`:
  - `tokenOnly`: never de-anonymize tool input fields.
  - `selectiveDeanonymize`: only de-anonymize fields listed in `allowedInputPaths`.
  - `trusted`: de-anonymize all string fields in tool input.
- `allowedInputPaths`: dot-style field paths for selective mode (example: `credentials.password`).
- `allowExternal`: permits non-Cloakd external tool execution where policy checks apply.
- `maxInputSize`: maximum serialized tool input size allowed.
- `maxOutputSize`: maximum returned output size before truncation/sanitization limits apply.

---

## Commands and Shortcuts

### Core commands

- `cloakd.activate` - Create Rulesheet
- `cloakd.openUI` - Open Main UI
- `cloakd.openRuleEditor` - Open Rule Editor
- `cloakd.switchRulesheet` - Switch Active Rulesheet
- `cloakd.showMappings` - Show Token Mappings
- `cloakd.clearMappings` - Clear Token Mappings
- `cloakd.anonymize` - Anonymize Selection
- `cloakd.quickAddRule` - Quick Add Rule

### Scanner commands

- `cloakd.scanCurrentFile` - Scan Current File for Secrets
- `cloakd.scanSecrets` - Scan File for Secrets
- `cloakd.scanIacFile` - Scan IaC File for Patterns

### Default shortcuts

- `Ctrl+Shift+A` - Quick Add Rule
- `Ctrl+Alt+S` - Scan Current File for Secrets
- `Ctrl+Alt+Shift+S` - Scan File for Secrets

---

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `cloakd.agent.maxToolRounds` | `10` | Maximum LM tool-call rounds in a chat loop |
| `cloakd.agent.executionMode` | `captured` | Tool execution mode: `captured` or `terminal` |
| `cloakd.agent.toolScope` | `cloakdOnly` | Expose only Cloakd tools or all tools |
| `cloakd.agent.dynamicToolWrapping.enabled` | `false` | Enable wrapped aliases for non-Cloakd tools |
| `cloakd.agent.dynamicToolWrapping.mode` | `strict` | Baseline wrapped-tool trust mode |
| `cloakd.agent.dynamicToolWrapping.policies` | `{}` | Optional default and per-tool policy overrides |
| `cloakd.mappings.autoClearOnSessionStart` | `true` | Clear token mappings when a new session starts |
| `cloakd.mappings.autoClearOnRulesheetSwitch` | `true` | Deprecated compatibility setting; switch clears mappings by policy |
| `cloakd.logging.level` | `warn` | Logging verbosity: `error`, `warn`, `info`, `debug` |

---

## Limitations

- Cloakd privacy guarantees are centered on `@Cloakd` chat participant flows.
- If you expose all tools and over-trust unknown tools, risk increases.
- Pattern quality affects anonymization quality. Poor regex patterns can over-match or miss values.

---

## Troubleshooting

### Main UI looks outdated

Run webview build and reload VS Code window:

1. `npm run webview:build`
2. Reload window

### Wrapped trust policy settings do not save

- Ensure extension is updated.
- Save from the `Wrapped Tool Trust Policy` submenu in main UI.
- If needed, reload VS Code so updated contributed settings metadata is picked up.

### Model still sees real values

1. Confirm your prompt is sent with `@Cloakd`.
2. Verify rules are enabled.
3. Test with a known sample value that should match.

---

## License

MIT.

---

## Support

Open a GitHub issue in the project repository with:

1. VS Code version
2. Cloakd version
3. Minimal reproduction steps
4. Redacted logs/screenshots
