<template>
  <main class="container">
    <!-- Header -->
    <header class="header">
      <div class="title-area">
        <span class="codicon codicon-shield" aria-hidden="true"></span>
        <h1 class="title">Cloakd</h1>
        <span class="workspace-badge" :title="'Active workspace: ' + workspaceName">{{ workspaceName }}</span>
        <span class="rulesheet-badge" :title="'Active rulesheet: ' + rulesheetName">{{ rulesheetName }}</span>
      </div>
    </header>

    <div class="scope-note" role="note" aria-live="polite">
      Anonymization is applied only when you chat with <strong>@Cloakd</strong>.
    </div>

    <section class="submenu-shell" aria-label="Cloakd controls">
      <details class="submenu-card" open>
        <summary class="submenu-summary">
          <span class="codicon codicon-list-filter" aria-hidden="true"></span>
          Rule Addition
        </summary>
        <div class="submenu-content">
          <RuleEditor
            :rules="rules"
            :view-mode="viewMode"
            :pending-scanned-rules="pendingScannedRules"
            :pending-imported-rules="pendingImportedRules"
            :validation-feedback="validationFeedback"
            :save-ack="saveAck"
            @save-rules="handleSaveRules"
            @save-single-rule="handleSaveSingleRule"
            @delete-rule="handleDeleteRule"
            @scan-current-file="handleScanCurrentFile"
            @scan-iac-file="handleScanIacFile"
            @scan-secrets="handleScanSecrets"
            @open-main-ui="handleOpenMainUi"
            @scanned-rules-consumed="pendingScannedRules = []"
            @import-rules="handleImportRules"
            @export-rules="handleExportRules"
            @imported-rules-consumed="pendingImportedRules = []"
          />
        </div>
      </details>

      <details class="submenu-card">
        <summary class="submenu-summary">
          <span class="codicon codicon-shield" aria-hidden="true"></span>
          Wrapped Tool Trust Policy
          <span class="submenu-status" :class="`state-${wrappingSaveState}`">{{ wrappingStatusLabel }}</span>
        </summary>
        <div class="submenu-content">
          <section class="tool-wrapping-panel" aria-label="Wrapped tool trust policy">
            <div class="tool-wrapping-controls">
              <label class="toggle-label">
                <input
                  type="checkbox"
                  :checked="wrappingEnabled"
                  @change="wrappingEnabled = ($event.target as HTMLInputElement).checked"
                />
                Enable dynamic wrapped tools
              </label>
              <label class="mode-label">
                Mode
                <select v-model="wrappingMode" class="mode-select" aria-label="Wrapped tool mode">
                  <option value="strict">Strict</option>
                  <option value="balanced">Balanced</option>
                  <option value="trustedLocal">Trusted Local</option>
                </select>
              </label>
            </div>
            <label class="policies-label" for="tool-policies-json">Policy Overrides JSON</label>
            <textarea
              id="tool-policies-json"
              v-model="wrappingPoliciesJson"
              class="policies-editor"
              spellcheck="false"
              aria-label="Wrapped tool policy JSON"
            ></textarea>
            <p v-if="wrappingError" class="wrapping-error">{{ wrappingError }}</p>
            <div class="tool-wrapping-actions">
              <vscode-button appearance="secondary" @click="saveToolWrappingConfig">Save Wrapped Tool Settings</vscode-button>
            </div>
          </section>
        </div>
      </details>
    </section>

    <!-- Loading overlay: shown until 'init' arrives from the extension host -->
    <Transition name="loading-fade">
      <div v-if="isLoading" class="loading-overlay" aria-label="Loading" role="status">
        <div class="loading-spinner" aria-hidden="true"></div>
        <span class="loading-text">Loading rules…</span>
      </div>
    </Transition>
  </main>
</template>

<script setup lang="ts">
import { computed, ref, onMounted } from 'vue';
import RuleEditor from './components/RuleEditor.vue';
import {
  provideVSCodeDesignSystem,
  vsCodeButton,
  vsCodeTextField
} from '@vscode/webview-ui-toolkit';

provideVSCodeDesignSystem().register(
  vsCodeButton(),
  vsCodeTextField()
);

const vscode = acquireVsCodeApi();

const rulesheetName = ref('Loading...');
const workspaceName = ref('Loading...');
const isLoading = ref(true);
const viewMode = ref<'main' | 'sidebar'>('main');
type WrappingMode = 'strict' | 'balanced' | 'trustedLocal';

interface SimpleRule {
  id: string;
  pattern: string;
  replacement: string;
  type: 'ip' | 'email' | 'uuid' | 'secret' | 'api-key' | 'path' | 'jwt' | 'private-key' | 'custom';
  enabled: boolean;
  description?: string;
}

interface ValidationFeedback {
  level: 'error' | 'warning';
  source: 'saveRules' | 'saveSingleRule' | 'unknown';
  messages: string[];
  timestamp: number;
}

interface SaveAck {
  ruleIds: string[];
  timestamp: number;
}

const rules = ref<SimpleRule[]>([]);
const validationFeedback = ref<ValidationFeedback | null>(null);
const saveAck = ref<SaveAck | null>(null);
const wrappingEnabled = ref(false);
const wrappingMode = ref<WrappingMode>('strict');
const wrappingPoliciesJson = ref('{}');
const wrappingSaveState = ref<'idle' | 'saving' | 'saved' | 'error'>('idle');
const wrappingError = ref('');

const wrappingStatusLabel = computed(() => {
  if (wrappingSaveState.value === 'saving') return 'Saving...';
  if (wrappingSaveState.value === 'saved') return 'Saved';
  if (wrappingSaveState.value === 'error') return 'Error';
  return 'Idle';
});

function handleSaveRules(newRules: SimpleRule[]) {
  rules.value = newRules;
  vscode.postMessage({ command: 'saveRules', rules: newRules });
}

function handleSaveSingleRule(rule: SimpleRule) {
  const idx = rules.value.findIndex(r => r.id === rule.id);
  if (idx !== -1) {
    rules.value[idx] = rule;
  } else {
    rules.value.push(rule);
  }
  vscode.postMessage({ command: 'saveSingleRule', rule });
}

function handleDeleteRule(ruleId: string) {
  rules.value = rules.value.filter(r => r.id !== ruleId);
  vscode.postMessage({ command: 'deleteRule', id: ruleId });
}

function handleScanCurrentFile() {
  vscode.postMessage({ command: 'scanCurrentFile' });
}

function handleScanIacFile() {
  vscode.postMessage({ command: 'scanIacFile' });
}

function handleScanSecrets() {
  vscode.postMessage({ command: 'scanSecrets' });
}

function handleOpenMainUi() {
  vscode.postMessage({ command: 'openMainUi' });
}

function handleImportRules() {
  vscode.postMessage({ command: 'importRules' });
}

function handleExportRules(rulesToExport: SimpleRule[]) {
  vscode.postMessage({ command: 'exportRules', rules: rulesToExport });
}

function saveToolWrappingConfig() {
  wrappingError.value = '';
  wrappingSaveState.value = 'saving';

  try {
    const parsedPolicies = JSON.parse(wrappingPoliciesJson.value || '{}');
    if (!parsedPolicies || typeof parsedPolicies !== 'object' || Array.isArray(parsedPolicies)) {
      throw new Error('Policy overrides must be a JSON object.');
    }

    vscode.postMessage({
      command: 'saveToolWrappingConfig',
      enabled: wrappingEnabled.value,
      mode: wrappingMode.value,
      policies: parsedPolicies,
    });
  } catch (error) {
    wrappingSaveState.value = 'error';
    wrappingError.value = error instanceof Error ? error.message : 'Invalid JSON payload.';
  }
}

/** Ref passed down to RuleEditor when scanned rules arrive */
const pendingScannedRules = ref<SimpleRule[]>([]);
const pendingImportedRules = ref<SimpleRule[]>([]);

window.addEventListener('message', (event) => {
  const msg = event.data;
  switch (msg.command) {
    case 'init':
      workspaceName.value = msg.workspaceName ?? 'Unknown Workspace';
      rulesheetName.value = msg.rulesheetName ?? 'Unknown';
      viewMode.value = msg.viewMode === 'sidebar' ? 'sidebar' : 'main';
      rules.value = msg.rules ?? [];
      wrappingEnabled.value = Boolean(msg.dynamicToolWrapping?.enabled);
      wrappingMode.value = msg.dynamicToolWrapping?.mode === 'balanced' || msg.dynamicToolWrapping?.mode === 'trustedLocal'
        ? msg.dynamicToolWrapping.mode
        : 'strict';
      wrappingPoliciesJson.value = JSON.stringify(msg.dynamicToolWrapping?.policies ?? {}, null, 2);
      wrappingSaveState.value = 'idle';
      wrappingError.value = '';
      isLoading.value = false;
      break;
    case 'scannedRules':
      pendingScannedRules.value = msg.rules ?? [];
      break;
    case 'importedRules':
      pendingImportedRules.value = msg.rules ?? [];
      break;
    case 'ruleValidation':
      validationFeedback.value = {
        level: msg.level === 'warning' ? 'warning' : 'error',
        source: msg.source === 'saveRules' || msg.source === 'saveSingleRule' ? msg.source : 'unknown',
        messages: Array.isArray(msg.messages) ? msg.messages : [],
        timestamp: Date.now(),
      };
      break;
    case 'rulesSaved':
      saveAck.value = {
        ruleIds: Array.isArray(msg.ruleIds) ? msg.ruleIds : [],
        timestamp: Date.now(),
      };
      break;
    case 'toolWrappingSaved':
      wrappingEnabled.value = Boolean(msg.dynamicToolWrapping?.enabled);
      wrappingMode.value = msg.dynamicToolWrapping?.mode === 'balanced' || msg.dynamicToolWrapping?.mode === 'trustedLocal'
        ? msg.dynamicToolWrapping.mode
        : 'strict';
      wrappingPoliciesJson.value = JSON.stringify(msg.dynamicToolWrapping?.policies ?? {}, null, 2);
      wrappingSaveState.value = 'saved';
      wrappingError.value = '';
      break;
    case 'toolWrappingSaveFailed':
      wrappingSaveState.value = 'error';
      wrappingError.value = String(msg.message ?? 'Failed to save wrapped tool settings.');
      break;
    case 'errorNotice':
      validationFeedback.value = {
        level: msg.level === 'warning' ? 'warning' : 'error',
        source: 'unknown',
        messages: [String(msg.message ?? 'An unexpected Cloakd error occurred.')],
        timestamp: Date.now(),
      };
      break;
  }
});

onMounted(() => {
  vscode.postMessage({ command: 'ready' });
});
</script>

<style scoped>
.container {
  display: flex;
  flex-direction: column;
  height: 100vh;
  box-sizing: border-box;
  overflow: hidden;
  position: relative;
}

.header {
  display: flex;
  align-items: center;
  padding: 14px 20px 12px;
  border-bottom: 1px solid var(--vscode-editorGroup-border);
  flex-shrink: 0;
}

.title-area {
  display: flex;
  align-items: center;
  gap: 10px;
}

.title-area .codicon {
  font-size: 17px;
  color: var(--vscode-textLink-foreground);
  opacity: 0.9;
}

.title {
  font-size: 16px;
  font-weight: 700;
  color: var(--vscode-editor-foreground);
  margin: 0;
  letter-spacing: -0.01em;
}

.rulesheet-badge,
.workspace-badge {
  display: inline-flex;
  align-items: center;
  font-size: 11px;
  font-weight: 500;
  padding: 2px 8px;
  border-radius: 10px;
  background-color: var(--vscode-badge-background);
  color: var(--vscode-badge-foreground);
  letter-spacing: 0.02em;
  max-width: 180px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.scope-note {
  margin: 10px 20px 8px;
  padding: 8px 10px;
  border-radius: 6px;
  border: 1px solid var(--vscode-editorInfo-border, var(--vscode-textLink-foreground));
  background-color: var(--vscode-editorInfo-background, transparent);
  color: var(--vscode-editorInfo-foreground, var(--vscode-editor-foreground));
  font-size: 12px;
  line-height: 1.4;
}

.submenu-shell {
  margin: 0 20px 12px;
  display: flex;
  flex-direction: column;
  gap: 10px;
  min-height: 0;
  overflow: auto;
  padding-right: 2px;
}

.submenu-card {
  border: 1px solid var(--vscode-editorWidget-border);
  border-radius: 8px;
  background: var(--vscode-editorWidget-background);
  overflow: hidden;
}

.submenu-summary {
  list-style: none;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 12px;
  font-size: 12px;
  font-weight: 700;
  color: var(--vscode-editor-foreground);
  border-bottom: 1px solid var(--vscode-editorWidget-border);
}

.submenu-summary::-webkit-details-marker {
  display: none;
}

.submenu-status {
  margin-left: auto;
  font-size: 11px;
  font-weight: 500;
  padding: 2px 8px;
  border-radius: 10px;
  background: var(--vscode-badge-background);
  color: var(--vscode-badge-foreground);
}

.submenu-status.state-saved {
  background: var(--vscode-testing-iconPassed, var(--vscode-badge-background));
}

.submenu-status.state-error {
  background: var(--vscode-testing-iconFailed, var(--vscode-badge-background));
}

.submenu-content {
  padding: 10px;
}

.tool-wrapping-panel {
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.tool-wrapping-controls {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 10px;
}

.toggle-label {
  font-size: 12px;
  color: var(--vscode-editor-foreground);
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.mode-label {
  font-size: 12px;
  color: var(--vscode-editor-foreground);
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.mode-select {
  border: 1px solid var(--vscode-dropdown-border);
  background: var(--vscode-dropdown-background);
  color: var(--vscode-dropdown-foreground);
  padding: 3px 6px;
  border-radius: 4px;
}

.policies-label {
  font-size: 12px;
  color: var(--vscode-descriptionForeground);
}

.policies-editor {
  width: 100%;
  min-height: 90px;
  resize: vertical;
  border-radius: 6px;
  border: 1px solid var(--vscode-input-border);
  background: var(--vscode-input-background);
  color: var(--vscode-input-foreground);
  padding: 8px;
  font-size: 12px;
  line-height: 1.35;
  box-sizing: border-box;
  font-family: var(--vscode-editor-font-family);
}

.tool-wrapping-actions {
  display: flex;
  justify-content: flex-end;
}

.wrapping-error {
  margin: 0;
  font-size: 12px;
  color: var(--vscode-errorForeground);
}

/* ─── Loading overlay ─────────────────────────────────────── */
.loading-overlay {
  position: absolute;
  inset: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 14px;
  background-color: var(--vscode-editor-background);
  z-index: 500;
}

.loading-spinner {
  width: 24px;
  height: 24px;
  border: 2px solid var(--vscode-editorGroup-border);
  border-top-color: var(--vscode-textLink-foreground);
  border-radius: 50%;
  animation: spin 0.7s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.loading-text {
  font-size: 12px;
  color: var(--vscode-descriptionForeground);
  letter-spacing: 0.02em;
}

/* Only a leave transition — the overlay is present immediately on mount */
.loading-fade-leave-active {
  transition: opacity 0.35s ease;
}
.loading-fade-leave-to {
  opacity: 0;
}
</style>