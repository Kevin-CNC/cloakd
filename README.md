# Cloakd (Originally: VS Prompt Hider)

<div align="center">
  <img src="./main/images/icon.svg" alt="Cloakd Logo" width="128" height="128"/>
  
  **Protect your secrets before they reach language models**
</div>

---

## 📋 Overview

**Cloakd** is a VS Code extension that automatically anonymizes sensitive values before prompts and tool payloads are sent to language models. It ensures that real secrets remain secure within your local environment while maintaining privacy throughout the LM interaction loop.

The extension provides intelligent pattern matching, token-based anonymization, and secure de-anonymization for tool execution—all while keeping sensitive data off-limits to external systems.

---

## 🎯 Problem & Solution

### Pain Points Solved

- **Secret Leakage**: Real secrets (API keys, passwords, IP addresses, AWS credentials) being accidentally sent to language models
- **Privacy Concerns**: Sensitive infrastructure details exposed in LLM prompts and responses
- **Tool Execution Risk**: De-anonymization happening at the wrong boundary, leaking secrets back to models
- **Manual Secret Management**: No unified way to define, manage, and apply anonymization rules across prompts

### Our Approach

Cloakd enforces a **hard privacy boundary**:

- ✅ Secrets anonymized **before** reaching the LM
- ✅ De-anonymization happens **only locally** in tool implementations  
- ✅ Tool outputs re-anonymized **before** returning to model
- ✅ Consistent token generation for reliable LM understanding

---

## ✨ Key Features

### 1. **Smart Anonymization Engine**
- Regex-based pattern matching with longest-first strategy to avoid overlaps
- Built-in patterns for common secrets: IPs, emails, UUIDs, API keys, JWT tokens, private keys, and more
- Custom rule support for domain-specific secrets
- Real-time pattern validation and conflict detection

### 2. **Webview Rule Editor**
- Intuitive Vue.js UI for creating and managing anonymization rules
- Per-workspace rule files (`.prompthider/<name>.prompthider.json`)
- Import/export rules for sharing across teams
- Visual feedback on unsaved changes and validation errors

### 3. **IaC Scanner**
- Terraform-specific detection pipeline (`.tf`, `.tfvars` files)
  - AWS account IDs, ARNs, AMI IDs, CIDR blocks, regions
  - Database credentials, API keys, secrets, bucket names
  - Private IP addresses and resource names
- Generic fallback for other file types
- Merge and deduplicate detected secrets into rule suggestions

### 4. **Token Mapping & Consistency**
- Automatic token generation with consistent mapping
- Maps original secrets to stable tokens (e.g., `IP_1`, `AWS_ACCOUNT_2`)
- Token instructions prepended to LM context for consistent usage
- Optional session and rulesheet auto-clear for token state

### 5. **LM Tool Integration**
Three built-in tools with full anonymization support:
- **prompthider_execute_command**: Run shell commands safely with output re-anonymization
- **prompthider_scp_transfer**: Secure file transfers with anonymized paths
- **prompthider_filesystem**: Read/write/patch/delete files with privacy enforcement

### 6. **@PromptHider Chat Participant**
- Seamlessly invoke within VS Code Chat
- Automatic prompt anonymization
- Full agentic loop support with configurable tool rounds
- Prior conversation history re-anonymized for context

---

## 🛠 Technology Stack

| Layer | Technology |
|-------|-----------|
| **Extension Core** | TypeScript, VS Code Extension API |
| **Webview UI** | Vue.js 3, Tailwind CSS, Vite |
| **Extension Build** | Webpack, Node.js |
| **File Format** | JSON (`*.prompthider.json`) |

---

## 🚀 Getting Started

### Installation

1. Open VS Code
2. Go to Extensions (Ctrl+Shift+X / Cmd+Shift+X)
3. Search for "Cloakd"
4. Click Install

### Quick Setup

1. **Open the Extension UI**
   - Run command: `PromptHider: Open UI`
   - Or use the sidebar view

2. **Create Your First Ruleset**
   - Click "New Ruleset" and name it (e.g., `my-project`)
   - A `.prompthider/my-project.prompthider.json` file is created

3. **Add Anonymization Rules**
   - Use the rule editor to define patterns
   - Leverage the IaC scanner to detect secrets in your code
   - Validate and save rules

4. **Use the Chat Participant**
   - In VS Code Chat, prefix your prompt with `@PromptHider`
   - Your message is automatically anonymized before reaching the LM

---

## 📖 Usage Examples

### Basic Rule Configuration

```json
{
  "version": "1.0.0",
  "enabled": true,
  "rules": [
    {
      "id": "rule-1",
      "type": "ip",
      "pattern": "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b",
      "replacement": "IP",
      "enabled": true,
      "description": "IPv4 addresses"
    },
    {
      "id": "rule-2",
      "type": "api-key",
      "pattern": "sk-[a-zA-Z0-9]{40,}",
      "replacement": "API_KEY",
      "enabled": true,
      "description": "OpenAI-like API keys"
    }
  ],
  "tokenConsistency": true,
  "autoAnonymize": true
}
```

### Chat Participant Usage

```
@PromptHider Can you help me debug this connection error?
The server at 192.168.1.100 is timing out when I call my API.
My credentials are sk-abc123def456...
```

→ **Sent to LM as:**
```
Can you help me debug this connection error?
The server at IP_1 is timing out when I call my API.
My credentials are API_KEY_1

[Token Mappings]
- IP_1 → 192.168.1.100
- API_KEY_1 → sk-abc123def456...
```

---

## ⚙️ Configuration

### Extension Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `prompthider.mappings.autoClearOnSessionStart` | `false` | Clear token mappings on new VS Code session |
| `prompthider.mappings.autoClearOnRulesheetSwitch` | `false` | Clear token mappings when switching rulesets |
| `prompthider.agent.maxToolRounds` | `10` | Max tool execution rounds in agentic loop |
| `prompthider.agent.executionMode` | `captured` | Tool mode: `captured` or `terminal` |
| `prompthider.agent.toolScope` | `all` | Available tools: `prompthiderOnly` or `all` |
| `prompthider.logging.level` | `info` | Log level: `debug`, `info`, `warn`, `error` |

---

## 📁 Project Structure

```
main/
  src/
    extension.ts                     # Activation, chat loop, command registry
    anonymizer/                      # Core anonymization logic
      AnonymizationEngine.ts         # Pattern matching & replacement
      PatternLibrary.ts              # Built-in patterns & rule types
      patternMatcher.ts              # Regex compilation & matching
      RuleValidator.ts               # Validation & conflict detection
      TokenManager.ts                # Token generation & mapping
    scanner/
      IacScanner.ts                  # IaC detection pipeline
    tools/
      CommandExecutor.ts             # Shell command execution tool
      ScpTransferTool.ts             # File transfer tool
      FileSystemTool.ts              # Filesystem operations tool
    ui/
      mainUiProvider.ts              # Main panel
      MappingsViewProvider.ts        # Token mappings sidebar
      RuleEditorProvider.ts          # Rule editor sidebar
  webview-ui/                        # Vue.js frontend
    src/
      App.vue                        # Root component
      components/RuleEditor.vue      # Rule editing UI
```

---

## 🔒 Privacy & Security

### Hard Rules

1. **Real secrets never reach the LM**
   - All input anonymized before `request.model.sendRequest()`
   
2. **De-anonymization only in local tools**
   - Secrets reconstructed only inside tool implementations
   - Never visible in LM-facing messages

3. **Tool outputs re-anonymized**
   - Results processed through anonymization before returning to model

4. **Persistent privacy boundary**
   - Token mappings stored in VS Code's `workspaceState`, never transmitted

---

## 🧪 Testing

Run the full test suite:

```bash
cd main
npm run test
```

Individual commands:

```bash
npm run compile        # TypeScript → JavaScript
npm run webview:build  # Vue app build
npm run lint          # Lint check
```

---

## 📝 Commands Reference

- `prompthider.activate` - Activate extension with rulesheet selection
- `prompthider.openUI` - Open main rule editor panel
- `prompthider.openRuleEditor` - Open sidebar rule editor
- `prompthider.showMappings` - Display current token mappings
- `prompthider.clearMappings` - Clear all token mappings
- `prompthider.scanIacFile` - Scan file for detectable secrets
- `prompthider.switchRulesheet` - Switch active ruleset
- `prompthider.quickAddRule` - Add a rule from command palette

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Follow the existing TypeScript/Vue code style
2. Run `npm run lint` before committing
3. Add tests for new features
4. Update docs if changing behavior

---

## 📄 License

[Add your license here]

---

## 🙋 Support

For issues, questions, or feature requests, please open an issue on the project repository.

---

<div align="center">
  <strong>Keep your secrets safe. Use Cloakd.</strong>
</div>
