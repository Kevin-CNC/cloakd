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

    <!-- Rule Editor -->
    <RuleEditor
      :rules="rules"
      :pending-scanned-rules="pendingScannedRules"
      :pending-imported-rules="pendingImportedRules"
      :validation-feedback="validationFeedback"
      :save-ack="saveAck"
      @save-rules="handleSaveRules"
      @save-single-rule="handleSaveSingleRule"
      @delete-rule="handleDeleteRule"
      @scan-iac-file="handleScanIacFile"
      @scanned-rules-consumed="pendingScannedRules = []"
      @import-rules="handleImportRules"
      @export-rules="handleExportRules"
      @imported-rules-consumed="pendingImportedRules = []"
    />

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
import { ref, onMounted } from 'vue';
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

function handleScanIacFile() {
  vscode.postMessage({ command: 'scanIacFile' });
}

function handleImportRules() {
  vscode.postMessage({ command: 'importRules' });
}

function handleExportRules(rulesToExport: SimpleRule[]) {
  vscode.postMessage({ command: 'exportRules', rules: rulesToExport });
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
      rules.value = msg.rules ?? [];
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