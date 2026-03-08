# Cloakd (formerly Vs Prompt Hider)

> **Privacy-First AI Development**: Automatically anonymize sensitive data before sending prompts to AI assistants and LLMs.

Cloakd is a VS Code extension that acts as a privacy-preserving middleware between you and AI assistants. It automatically detects and anonymizes sensitive information (IPs, emails, API keys, credentials, file paths, and more) in your prompts, replacing them with consistent, reversible tokens that can be de-anonymized locally before execution.

**Perfect for:**
- 🔒 Sharing code with AI assistants without exposing secrets
- 🛡️ Collaborating on sensitive infrastructure code
- 📋 Privacy-first development with copilot-style assistants
- 🔄 Maintaining security while leveraging AI tools

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Guide](#usage-guide)
  - [Creating Your First Rulesheet](#creating-your-first-rulesheet)
  - [Opening the Main UI](#opening-the-main-ui)
  - [Anonymizing Content](#anonymizing-content)
  - [Managing Token Mappings](#managing-token-mappings)
  - [Scanning IaC Files](#scanning-iac-files)
  - [Using with AI Assistants](#using-with-ai-assistants)
- [Configuration](#configuration)
  - [Settings](#settings)
  - [Rulesheet Format](#rulesheet-format)
  - [Built-in Patterns](#built-in-patterns)
  - [Custom Rules](#custom-rules)
- [Architecture](#architecture)
  - [Component Overview](#component-overview)
  - [anonymizer/](#anonymizer)
  - [ui/](#ui)
  - [tools/](#tools)
  - [scanner/](#scanner)
- [Commands Reference](#commands-reference)
- [AI Integration](#ai-integration)
  - [Chat Participants](#chat-participants)
  - [Language Model Tools](#language-model-tools)
- [Token Mappings & Consistency](#token-mappings--consistency)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

---

## Features

### 🔍 **Automatic Pattern Detection**
- **IP Addresses**: IPv4 and IPv6 detection
- **Email Addresses**: Professional and personal emails
- **API Keys**: AWS, GitHub, OpenAI, Google, and more
- **UUIDs & GUIDs**: Unique identifiers
- **JWTs & Tokens**: Authentication tokens
- **Private Keys**: SSH and cryptographic keys
- **File Paths**: Local and remote file paths
- **Custom Patterns**: Define your own regex rules

### 🎯 **Smart Anonymization**
- **Consistent Token Replacement**: Same sensitive value always maps to the same token across sessions
- **Reversible Mappings**: De-anonymize locally before executing commands
- **Visual Previews**: See anonymization changes before applying them
- **Selective Control**: Enable/disable specific pattern types
- **Custom Rules**: Define organization-specific patterns

### 🖥️ **Intuitive User Interface**
- **Main Dashboard**: View and manage all anonymization rules
- **Rule Editor**: Create, edit, and test custom patterns
- **Mappings View**: Monitor active token-to-value mappings
- **IaC Scanner**: Scan Infrastructure-as-Code files for sensitive data
- **Sidebar Integration**: Quick access to rules and mappings

### 🤖 **AI Assistant Integration**
- **Copilot Support**: Chat participant for direct AI integration
- **Command Execution Tool**: Execute commands with automatic de-anonymization
- **SCP Transfer Tool**: Transfer files securely via SCP with token resolution
- **Seamless Workflow**: Anonymize → Share with AI → Auto-deanonymize → Execute

### ⚙️ **Developer-Friendly**
- **JSON Rulesheet Format**: Easy to version control and share
- **Configuration API**: Customize behavior via VS Code settings
- **Hot Reload**: Changes reflect immediately
- **Debug Support**: F5 debugging for development

---

## Installation

### From VS Code Extensions Marketplace

1. Open VS Code
2. Go to Extensions (Ctrl+Shift+X / Cmd+Shift+X)
3. Search for "Cloakd"
4. Click Install

### From GitHub (Development)

1. Clone the repository:
   ```bash
   git clone https://github.com/Kevin-CNC/vs-prompt-hider.git
   cd vs-prompt-hider/main
   ```

2. Install dependencies:
   ```bash
   npm install
   cd webview-ui && npm install && cd ..
   ```

3. Build the webview:
   ```bash
   npm run webview:build
   ```

4. Compile the extension:
   ```bash
   npm run compile
   ```

5. Press `F5` to launch the extension in a new VS Code window

---

## Quick Start

### 1. Initialize a Rulesheet

When you first open VS Code with the extension, you'll be prompted to create a rulesheet:

```bash
Cmd+Shift+P → Cloakd: Create Rulesheet
```

Choose a name for your rulesheet (or use the default "defaultSheet"). A `.cloakd.json` file will be created in your workspace root.

### 2. Enable Auto-Anonymization

Go to VS Code Settings and enable:
- `cloakd.autoAnonymize`: true

### 3. Share Sensitive Code with AI

1. Copy code containing secrets
2. The extension automatically detects and anonymizes sensitive patterns
3. Share with your AI assistant (Copilot, ChatGPT, Claude, etc.)
4. Use the integrated tools to execute commands with auto-deanonymization

### 4. Monitor Token Mappings

Open the Mappings View in the sidebar to see all active tokens:

```bash
Cmd+Shift+P → Cloakd: Show Token Mappings
```

---

## Usage Guide

### Creating Your First Rulesheet

The first time you activate the extension, it will search your workspace for `.cloakd.json` files. If none exist, you'll be prompted to create one:

```json
{
  "rules": [
    {
      "id": "ipv4",
      "type": "ip",
      "pattern": "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b",
      "replacement": "IP_{index}",
      "enabled": true,
      "description": "IPv4 addresses"
    }
  ],
  "autoAnonymize": true,
  "showPreview": true
}
```

The rulesheet is automatically added to `.gitignore` and `.copilotignore` to prevent accidental commits of sensitive mappings.

### Opening the Main UI

```bash
Cmd+Shift+P → Cloakd: Open Main UI
```

The Main UI provides:
- Overview of all active rules
- Current token mappings
- Quick access to rule editor
- Statistics on anonymized content
- Settings and configuration

### Anonymizing Content

#### Method 1: Auto-Anonymization
If enabled, sensitive data is automatically detected and replaced when you copy content.

#### Method 2: Manual Selection
1. Select text in your editor
2. Right-click → "Anonymize Selection"
   - Or: `Cmd+Shift+P` → `Cloakd: Anonymize Selection`
3. Review the preview
4. Confirm anonymization

#### Method 3: Scan Entire File
```bash
Cmd+Shift+P → Cloakd: Scan IaC File for Patterns
```

This scans the current file and highlights all matched patterns.

### Managing Token Mappings

#### View Mappings
```bash
Cmd+Shift+P → Cloakd: Show Token Mappings
```

Shows all current token → value mappings in a panel.

#### Clear Mappings
```bash
Cmd+Shift+P → Cloakd: Clear Token Mappings
```

Resets all mappings. Use with caution—previous tokens will no longer map to original values.

### Scanning IaC Files

Use the IaC Scanner to detect sensitive data in Infrastructure-as-Code files:

```bash
Cmd+Shift+P → Cloakd: Scan IaC File for Patterns
```

The scanner will:
1. Analyze the current file for patterns
2. Highlight matches
3. Display matches in a sidebar panel
4. Allow quick anonymization of detected patterns

Supported files:
- Terraform (`.tf`)
- CloudFormation (`.yaml`, `.yml`, `.json`)
- Kubernetes (`.yaml`, `.yml`)
- Docker (`.dockerfile`)
- And more...

### Using with AI Assistants

#### With GitHub Copilot
Cloakd integrates as a chat participant in VS Code:

```
@cloakd Help me debug this SSH configuration issue
```

The participant will:
1. Detect sensitive data in the context
2. Anonymize it automatically
3. Send the anonymized version to the AI
4. Help execute commands with automatic de-anonymization

#### With Other Assistants
1. Open the Main UI
2. Anonymize your content manually
3. Copy the anonymized text
4. Paste into your AI assistant
5. Use the integrated Command Execution or SCP Transfer tools via the LM Tool API

#### Language Model Tools
Two tools are automatically available to AI assistants:

**cloakd_execute_command**
- Executes shell commands with automatic de-anonymization
- Accepts anonymized tokens (e.g., `ssh IP_1`, `curl -H Authorization: API_KEY_1`)
- Locally resolves tokens before execution
- Example:
  ```
  {
    "command": "ssh user@IP_1 -p PORT_1"
  }
  ```

**cloakd_scp_transfer**
- Transfers files via SCP with token resolution
- Supports anonymized paths and server addresses
- Example:
  ```
  {
    "source": "local/config.yaml",
    "destination": "user@HOST_1:/etc/app/config.yaml",
    "recursive": false
  }
  ```

---

## Configuration

### Settings

All settings are configurable via VS Code Settings (Preferences → Settings):

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `cloakd.autoAnonymize` | boolean | `true` | Automatically anonymize detected sensitive data |
| `cloakd.showPreview` | boolean | `true` | Show preview before anonymizing |
| `cloakd.tokenConsistency` | boolean | `true` | Use consistent tokens across sessions |
| `cloakd.enabledPatterns` | array | `["ip", "email", "uuid", "api-key"]` | List of enabled pattern types |

Example `settings.json`:
```json
{
  "cloakd.autoAnonymize": true,
  "cloakd.showPreview": false,
  "cloakd.tokenConsistency": true,
  "cloakd.enabledPatterns": ["ip", "email", "api-key", "custom"]
}
```

### Rulesheet Format

Rulesheets are stored as `.cloakd.json` files in JSON format:

```json
{
  "version": "1.0",
  "rules": [
    {
      "id": "my_rule_id",
      "type": "custom",
      "pattern": "\\b[A-Z]{3}\\d{6}\\b",
      "replacement": "TICKET_{index}",
      "enabled": true,
      "description": "Internal ticket numbers"
    }
  ],
  "options": {
    "autoAnonymize": true,
    "showPreview": true,
    "tokenConsistency": true
  }
}
```

### Built-in Patterns

The extension includes the following built-in patterns:

| Pattern | ID | Description | Example | Replacement |
|---------|----|----|---------|-------------|
| **IPv4** | `ipv4` | IPv4 addresses | `192.168.1.1` | `IP_1` |
| **IPv6** | `ipv6` | IPv6 addresses | `2001:0db8:85a3::8a2e:0370:7334` | `IPV6_1` |
| **Email** | `email` | Email addresses | `user@example.com` | `USER_1@domain.tld` |
| **API Keys** | `api-keys` | AWS, GitHub, OpenAI, Google keys | `ghp_abc123...` | `API_KEY_1` |
| **UUID** | `uuid` | UUID/GUID values | `550e8400-e29b-41d4-a716-446655440000` | `UUID_1` |
| **JWT** | `jwt` | JWT tokens | `eyJhbGciOiJIUzI1NiIs...` | `JWT_1` |
| **Private Key** | `private-key` | RSA, SSH private keys | `-----BEGIN PRIVATE KEY-----` | `PRIVATE_KEY_1` |
| **File Path** | `path` | File and directory paths | `/home/user/secret.key` | `FILE_PATH_1` |

### Custom Rules

Create custom rules for organization-specific patterns. Edit your `.cloakd.json` rulesheet:

```json
{
  "rules": [
    {
      "id": "credit_card",
      "type": "custom",
      "pattern": "\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b",
      "replacement": "CARD_{index}",
      "enabled": true,
      "description": "Credit card numbers"
    },
    {
      "id": "customer_id",
      "type": "custom",
      "pattern": "CUST_\\d{8}",
      "replacement": "CUSTOMER_{index}",
      "enabled": true,
      "description": "Internal customer IDs"
    },
    {
      "id": "database_connection",
      "type": "custom",
      "pattern": "postgres://[^\\s]+|mongodb://[^\\s]+",
      "replacement": "DB_CONNECTION_{index}",
      "enabled": false,
      "description": "Database connection strings"
    }
  ]
}
```

#### Pattern Tips

- **Use raw regex strings**: No need to escape backslashes twice (use `\\d{4}` not `\\\\d{4}`)
- **Global flag**: Patterns are automatically matched globally; don't add `/g` flag
- **Case sensitivity**: Patterns are case-sensitive by default
- **Test patterns**: Use the Rule Editor UI to test patterns before saving

---

## Architecture

### Component Overview

Cloakd is organized into modular components:

```
src/
├── anonymizer/           # Core anonymization logic
├── ui/                   # VS Code UI providers (webviews)
├── tools/                # LM tools for AI integration
├── scanner/              # IaC file scanning
├── utils/                # Utilities (config, etc.)
└── extension.ts          # Main extension entry point
```

### `anonymizer/`

Core anonymization engine:

- **AnonymizationEngine**: Main engine that detects and replaces sensitive data
- **PatternLibrary**: Built-in pattern definitions
- **patternMatcher**: Regex-based pattern matching
- **TokenManager**: Manages token-to-value mappings (persistent across sessions)
- **RuleValidator**: Validates rule syntax and regex patterns

### `ui/`

VS Code webview providers for user interfaces:

- **mainUiProvider**: Main dashboard with rules overview and statistics
- **RuleEditorProvider**: Web-based rule editor with live validation
- **MappingsViewProvider**: View and manage token mappings
- **Extension uses Vue 3 + Tailwind CSS** for the webview UI

### `tools/`

AI integration tools:

- **CommandExecutor**: Executes shell commands with automatic de-anonymization
- **ScpTransferTool**: SCP file transfer with token resolution

### `scanner/`

Infrastructure-as-Code scanning:

- **IacScanner**: Detects patterns in IaC files, highlights matches, supports multiple formats

---

## Commands Reference

All commands are accessible via Command Palette (`Cmd+Shift+P` / `Ctrl+Shift+P`):

### Main Commands

| Command | Title | Keybinding | Description |
|---------|-------|-----------|-------------|
| `cloakd.activate` | Create Rulesheet | — | Initialize a new rulesheet in the workspace |
| `cloakd.openUI` | Open Main UI | — | Open the main dashboard webview |
| `cloakd.clearMappings` | Clear Token Mappings | — | Reset all token mappings |
| `cloakd.scanIacFile` | Scan IaC File for Patterns | — | Scan current file for sensitive data |

### Quick Actions

| Command | Title | Context | Description |
|---------|-------|---------|-------------|
| `cloakd.anonymize` | Anonymize Selection | Selection | Anonymize selected text |
| `cloakd.openRuleEditor` | Open Rule Editor | — | Open the rule editor webview |
| `cloakd.showMappings` | Show Token Mappings | — | Display current token mappings |

---

## AI Integration

### Chat Participants

Cloakd registers as a chat participant that integrates with copilot-style AI assistants:

```
@cloakd [your message here]
```

The participant:
- Detects sensitive data in your message and context
- Automatically anonymizes before sending to AI
- Provides access to Language Model Tools

### Language Model Tools

AI assistants have access to two tools for secure operations:

#### `cloakd_execute_command`

Executes shell commands with automatic de-anonymization:

```
Command: "ssh user@IP_1 -c 'cat /etc/config' > FILE_PATH_2"
```

The tool will resolve tokens back to original values before executing:
- `IP_1` → Original IP address
- `FILE_PATH_2` → Original file path

#### `cloakd_scp_transfer`

Transfers files securely via SCP:

```
Source: "local/deployment.yaml"
Destination: "user@HOST_1:/opt/deploy/deployment.yaml"
Recursive: false
```

---

## Token Mappings & Consistency

### How Token Consistency Works

1. **First Detection**: When sensitive data is detected, a unique token is created (e.g., `IP_1`)
2. **Mapping Storage**: The token → value mapping is stored in the workspace's local mappings file
3. **Future References**: The same value always maps to the same token in the session
4. **Persistence**: If enabled (`cloakd.tokenConsistency: true`), mappings persist across sessions
5. **De-anonymization**: When commands are executed, tokens are automatically replaced with original values

### Viewing Mappings

The Mappings View shows all active tokens:

```
IP_1 → 192.168.1.100
USER_1 → admin@example.com
API_KEY_1 → sk-abc123def456...
PRIVATE_KEY_1 → -----BEGIN PRIVATE KEY-----...
```

### Resetting Mappings

Clear all mappings with:

```bash
Cmd+Shift+P → Cloakd: Clear Token Mappings
```

⚠️ **Warning**: This will break de-anonymization for previous tokens.

---

## Troubleshooting

### Extension Not Activating

**Issue**: Extension loads but no rulesheet found.

**Solution**: 
- Run `Cloakd: Create Rulesheet` to initialize
- Check if `.cloakd.json` exists in workspace root
- Verify file is valid JSON

### Patterns Not Matching

**Issue**: Sensitive data not being detected.

**Solutions**:
1. Check if pattern is enabled: Open Main UI → Rules
2. Verify regex pattern:
   - Use `/` delimiters in rule editor (e.g., `/\d+/` not `\d+`)
   - Test pattern against sample data
3. Check pattern type is in `enabledPatterns` setting

### Tokens Not De-anonymizing

**Issue**: Commands executed with tokens show token values, not original.

**Solution**:
- Ensure mappings exist: `Cloakd: Show Token Mappings`
- Don't clear mappings before executing commands
- Check token format matches (e.g., `IP_1`, not `IP_01`)

### UI Not Loading

**Issue**: Main UI webview is blank or shows errors.

**Solutions**:
1. Rebuild webview: `npm run webview:build`
2. Recompile extension: `npm run compile`
3. Reload VS Code window: `Cmd+Shift+P` → `Developer: Reload Window`

### Performance Issues

**Issue**: Extension slows down editor.

**Solutions**:
1. Disable patterns you don't need:
   ```json
   {
     "cloakd.enabledPatterns": ["ip", "email"]
   }
   ```
2. Disable auto-anonymization: `cloakd.autoAnonymize: false`
3. Check for large rulesheet files and optimize patterns

---

## Development

### Prerequisites

- Node.js 16+ and npm
- VS Code 1.85.0+
- TypeScript knowledge

### Build & Debug

1. **Install dependencies**:
   ```bash
   npm install
   cd webview-ui && npm install && cd ..
   ```

2. **Build webview**:
   ```bash
   npm run webview:build
   ```

3. **Compile extension**:
   ```bash
   npm run compile
   ```

4. **Start debugging**:
   - Press `F5` or run `npm run watch` in one terminal and debug in VS Code

### Project Structure

```
main/
├── src/
│   ├── anonymizer/        # Anonymization engine
│   ├── ui/                # VS Code webview providers
│   ├── tools/             # AI integration tools
│   ├── scanner/           # IaC scanning
│   ├── utils/             # Utilities
│   └── extension.ts       # Entry point
├── webview-ui/            # Vue 3 + Tailwind webview app
├── dist/                  # Compiled extension output
├── package.json           # Extension manifest
└── webpack.config.js      # Build configuration
```

### Build Commands

| Command | Purpose |
|---------|---------|
| `npm run compile` | Compile TypeScript → JavaScript |
| `npm run watch` | Watch mode (recompile on changes) |
| `npm run package` | Production build with minification |
| `npm run webview:build` | Build Vue webview |
| `npm run compile-tests` | Compile test files |

### Testing

Run tests:
```bash
npm run test
```

### Extending the Extension

#### Adding a New Pattern

1. Edit `src/anonymizer/PatternLibrary.ts`
2. Add to `BUILTIN_PATTERNS` array:
   ```typescript
   {
     id: 'my-pattern',
     type: 'custom',
     pattern: /your-regex/g,
     replacement: 'TOKEN_{index}',
     enabled: true,
     description: 'Your description'
   }
   ```

#### Adding a New Command

1. Register in `package.json` > `contributes.commands`
2. Implement in `src/extension.ts` > `activate()`
3. Example:
   ```typescript
   context.subscriptions.push(
     vscode.commands.registerCommand('cloakd.myCommand', () => {
       vscode.window.showInformationMessage('Hello!');
     })
   );
   ```

#### Adding a New UI Component

1. Create `RuleEditorProvider.ts` style provider in `src/ui/`
2. Build Vue component in `webview-ui/src/components/`
3. Register in `src/extension.ts`

---

## Contributing

Contributions are welcome! Here's how to help:

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/amazing-feature`
3. **Commit** changes: `git commit -m 'Add amazing feature'`
4. **Push** to branch: `git push origin feature/amazing-feature`
5. **Open** a Pull Request

### Development Guidelines

- Follow existing code style (TypeScript)
- Add JSDoc comments for public APIs
- Test changes thoroughly
- Update README if adding features
- Keep commits atomic and descriptive

### Reporting Issues

Found a bug? Open an issue on GitHub with:
- Clear title and description
- Steps to reproduce
- Expected vs. actual behavior
- VS Code version and extension version

---

## License

MIT © 2026 Kevin Chen

This extension is provided as-is for privacy-focused development. Use responsibly.

---

## Recommended VS Code Extensions

- **Thunder Client**: REST API testing (pairs well with token de-anonymization)
- **Terraform**: IaC file support
- **Docker**: Container file support
- **GitLens**: Git integration (for viewing committed rulesheet changes)

---

## FAQ

**Q: Will this slow down my editor?**  
A: No. Anonymization runs asynchronously and is optimized for performance. You can disable auto-anonymization in settings if needed.

**Q: Can I share my rulesheet with team members?**  
A: Yes! Commit the `.cloakd.json` file to your repository. Mappings files are local-only and in `.gitignore`.

**Q: Is my data sent anywhere?**  
A: No. Everything runs locally. Tokens are only generated and stored on your machine.

**Q: Can I undo anonymization?**  
A: Yes, as long as mappings exist. Use `Cloakd: Clear Token Mappings` only when you want to reset.

**Q: Does this work with all AI assistants?**  
A: It works best with GitHub Copilot (chat participant integration). For other assistants, manually copy anonymized content.

---

**Happy secure coding! 🔒**
