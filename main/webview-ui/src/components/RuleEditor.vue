<template>
  <div class="rule-editor-container">
    <div class="search-bar-wrapper">
      <div class="search-toolbar">
        <vscode-text-field
          :value="searchQuery"
          @input="onSearchInput"
          placeholder="Search patterns, replacements, or descriptions..."
          class="search-bar"
          aria-label="Search rules"
        >
          <span slot="start" class="codicon codicon-search"></span>
        </vscode-text-field>
        <vscode-button
          appearance="secondary"
          class="help-toggle"
          @click="toggleHelpPanel"
          :title="showHelpPanel ? 'Hide keybindings and controls' : 'Show keybindings and controls'"
          aria-label="Toggle keybindings and controls help"
        >
          <span slot="start" class="codicon" :class="showHelpPanel ? 'codicon-chevron-up' : 'codicon-question'"></span>
          {{ showHelpPanel ? 'Hide Help' : 'Help' }}
        </vscode-button>
      </div>

      <ul v-if="showSuggestions && filteredSuggestions.length > 0" class="autocomplete-list" role="listbox">
        <li
          v-for="(suggestion, idx) in filteredSuggestions"
          :key="idx"
          class="autocomplete-item"
          @mousedown.prevent="applySuggestion(suggestion)"
        >
          {{ suggestion }}
        </li>
      </ul>
    </div>

    <Transition name="fade">
      <section v-if="showHelpPanel" class="help-panel" aria-label="Keybindings and controls help">
        <div class="help-grid">
          <article class="help-card">
            <h3 class="help-title">Keybindings</h3>
            <div v-for="entry in keybindingEntries" :key="entry.label" class="help-entry">
              <div class="help-entry-top">
                <strong>{{ entry.label }}</strong>
                <kbd class="shortcut">{{ entry.shortcut }}</kbd>
              </div>
              <p>{{ entry.description }}</p>
            </div>
          </article>
        </div>
      </section>
    </Transition>

    <div class="rules-grid-wrapper">
      <div class="grid-header" aria-hidden="true">
        <div class="col-pattern">Pattern (Regex or Wildcard)</div>
        <div class="col-replacement">Replacement</div>
        <div class="col-type">Type</div>
        <div class="col-enabled">Enabled</div>
        <div class="col-description">Description</div>
        <div class="col-actions">Actions</div>
      </div>

      <Transition name="fade">
        <div v-if="localRules.length === 0" class="empty-state">
          <span class="codicon codicon-filter" aria-hidden="true"></span>
          <p class="empty-title">No rules yet</p>
          <p class="empty-sub">Click <strong>Add Rule</strong> to create your first anonymization pattern.</p>
        </div>
      </Transition>

      <Transition name="fade">
        <div v-if="localRules.length > 0 && filteredRules.length === 0" class="empty-state">
          <span class="codicon codicon-search" aria-hidden="true"></span>
          <p class="empty-title">No matches</p>
          <p class="empty-sub">Try a different search term for pattern, replacement, or description.</p>
        </div>
      </Transition>

      <TransitionGroup name="rule-row" tag="div" class="grid-body">
        <div
          v-for="(rule, index) in filteredRules"
          :key="rule.id"
          class="grid-row"
          :class="{ 'row-dirty': dirtyIds.has(rule.id) }"
          role="row"
          :aria-label="`Rule ${index + 1}`"
        >
          <span
            v-if="dirtyIds.has(rule.id)"
            class="dirty-bar"
            title="Unsaved changes"
            aria-label="Unsaved changes"
          ></span>

          <div class="col-pattern">
            <vscode-text-field
              :value="rule.pattern"
              @input="updateRule(rule.id, 'pattern', ($event.target as HTMLInputElement).value)"
              placeholder="e.g., 10.123.*.* or \b\d{1,3}(\.\d{1,3}){3}\b"
              class="field-full"
              aria-label="Pattern"
            ></vscode-text-field>
          </div>

          <div class="col-replacement">
            <vscode-text-field
              :value="rule.replacement"
              @input="updateRule(rule.id, 'replacement', ($event.target as HTMLInputElement).value)"
              placeholder="e.g., IP_TOKEN"
              class="field-full"
              aria-label="Replacement token"
            ></vscode-text-field>
          </div>

          <div class="col-type">
            <select
              :value="rule.type"
              @change="updateRule(rule.id, 'type', ($event.target as HTMLSelectElement).value)"
              class="rule-select"
              aria-label="Type"
            >
              <option value="ip">ip</option>
              <option value="email">email</option>
              <option value="uuid">uuid</option>
              <option value="secret">secret</option>
              <option value="api-key">api-key</option>
              <option value="path">path</option>
              <option value="jwt">jwt</option>
              <option value="private-key">private-key</option>
              <option value="custom">custom</option>
            </select>
          </div>

          <div class="col-enabled">
            <label class="checkbox-wrap" :title="rule.enabled ? 'Rule enabled' : 'Rule disabled'">
              <input
                type="checkbox"
                :checked="rule.enabled"
                @change="updateRule(rule.id, 'enabled', ($event.target as HTMLInputElement).checked)"
                aria-label="Enabled"
              />
            </label>
          </div>

          <div class="col-description">
            <vscode-text-field
              :value="rule.description || ''"
              @input="updateRule(rule.id, 'description', ($event.target as HTMLInputElement).value)"
              placeholder="Optional description"
              class="field-full"
              aria-label="Description"
            ></vscode-text-field>
          </div>

          <div class="col-actions">
            <vscode-button
              appearance="icon"
              @click="saveSingleRule(rule.id)"
              :title="dirtyIds.has(rule.id) ? 'Save this rule' : 'Rule saved'"
              aria-label="Save rule"
            >
              <span class="codicon codicon-save"></span>
            </vscode-button>
            <vscode-button
              appearance="icon"
              @click="requestRemoveRule(rule.id)"
              title="Delete rule"
              aria-label="Delete rule"
              class="btn-danger"
            >
              <span class="codicon codicon-trash"></span>
            </vscode-button>
          </div>
        </div>
      </TransitionGroup>
    </div>

    <div class="footer-actions">
      <vscode-button appearance="primary" @click="addRule">
        <span slot="start" class="codicon codicon-add"></span>
        Add Rule
      </vscode-button>
      <vscode-button appearance="secondary" @click="emit('importRules')">
        <span slot="start" class="codicon codicon-cloud-upload"></span>
        Import Rules
      </vscode-button>
      <vscode-button appearance="secondary" @click="exportRules">
        <span slot="start" class="codicon codicon-cloud-download"></span>
        Export Rules
      </vscode-button>
      <vscode-button appearance="secondary" @click="emit('scanIacFile')">
        <span slot="start" class="codicon codicon-search"></span>
        Scan IaC File
      </vscode-button>
      <vscode-button appearance="secondary" @click="emit('scanSecrets')">
        <span slot="start" class="codicon codicon-shield"></span>
        Scan File...
      </vscode-button>
      <vscode-button v-if="props.viewMode === 'sidebar'" appearance="secondary" @click="emit('openMainUi')" title="Open the full Cloakd panel">
        <span slot="start" class="codicon codicon-window"></span>
        Open Main UI
      </vscode-button>
      <vscode-button
        appearance="secondary"
        @click="confirmRules"
        :disabled="dirtyIds.size === 0 || undefined"
        title="Save all modified rules"
      >
        <span slot="start" class="codicon codicon-save-all"></span>
        Save All
      </vscode-button>
    </div>

    <div class="toast-region" aria-live="polite" aria-atomic="false">
      <TransitionGroup name="toast">
        <div
          v-for="toast in toasts"
          :key="toast.id"
          class="toast"
          :class="'toast--' + toast.type"
          role="status"
        >
          <span class="codicon" :class="toastIconClass(toast.type)" aria-hidden="true"></span>
          {{ toast.message }}
        </div>
      </TransitionGroup>
    </div>

    <Transition name="dialog">
      <div v-if="ruleToDelete" class="dialog-overlay" role="presentation" @click.self="cancelRemoveRule">
        <div
          class="dialog-content"
          role="alertdialog"
          aria-modal="true"
          aria-labelledby="dialog-title"
          aria-describedby="dialog-description"
        >
          <div class="dialog-icon">
            <span class="codicon codicon-warning" aria-hidden="true"></span>
          </div>
          <h2 id="dialog-title" class="dialog-title">Delete Rule</h2>
          <p id="dialog-description" class="dialog-description">
            Delete pattern <code class="pattern-preview">{{ ruleToDelete.pattern || '(empty)' }}</code>?
            This cannot be undone.
          </p>
          <div class="dialog-actions">
            <vscode-button appearance="secondary" @click="cancelRemoveRule">Cancel</vscode-button>
            <vscode-button appearance="primary" @click="confirmRemoveRule" class="btn-delete-confirm">
              Delete
            </vscode-button>
          </div>
        </div>
      </div>
    </Transition>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue';

export interface RuleRow {
  id: string;
  pattern: string;
  replacement: string;
  type: 'ip' | 'email' | 'uuid' | 'secret' | 'api-key' | 'path' | 'jwt' | 'private-key' | 'custom';
  enabled: boolean;
  description?: string;
}

interface Toast {
  id: number;
  message: string;
  type: 'success' | 'error' | 'warning';
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

interface HelpEntry {
  label: string;
  description: string;
  shortcut?: string;
}

const props = defineProps<{
  rules: RuleRow[];
  viewMode?: 'main' | 'sidebar';
  pendingScannedRules?: RuleRow[];
  pendingImportedRules?: RuleRow[];
  validationFeedback?: ValidationFeedback | null;
  saveAck?: SaveAck | null;
}>();

const emit = defineEmits<{
  (e: 'saveRules', rules: RuleRow[]): void;
  (e: 'saveSingleRule', rule: RuleRow): void;
  (e: 'deleteRule', ruleId: string): void;
  (e: 'scanCurrentFile'): void;
  (e: 'scanIacFile'): void;
  (e: 'scanSecrets'): void;
  (e: 'openMainUi'): void;
  (e: 'importRules'): void;
  (e: 'exportRules', rules: RuleRow[]): void;
  (e: 'scannedRulesConsumed'): void;
  (e: 'importedRulesConsumed'): void;
}>();

const localRules = ref<RuleRow[]>([]);
const ruleToDelete = ref<RuleRow | null>(null);
const dirtyIds = ref<Set<string>>(new Set());
const showHelpPanel = ref(false);

const searchQuery = ref('');
const showSuggestions = ref(false);
const suggestions = ref<string[]>([]);

const keybindingEntries: HelpEntry[] = [
  {
    label: 'Quick Add Rule',
    shortcut: 'Ctrl+Shift+A',
    description: 'Build a new anonymization rule from the text currently selected in the editor.',
  },
  {
    label: 'Scan Current File',
    shortcut: 'Ctrl+Alt+S',
    description: 'Analyze the active editor and push likely secret findings into the Cloakd UI for review.',
  },
  {
    label: 'Scan File Picker',
    shortcut: 'Ctrl+Alt+Shift+S',
    description: 'Open a file picker and scan a saved file without changing the active editor tab.',
  },
  {
    label: 'Wildcard Patterns',
    description: 'Use * for any sequence and ? for a single character (for example: 10.123.*.* or *@ambrosio.com).',
  },
];

const filteredSuggestions = computed(() => {
  if (!searchQuery.value.trim()) return [];
  const q = searchQuery.value.toLowerCase();
  return suggestions.value.filter(s => s.toLowerCase().includes(q)).slice(0, 8);
});

const filteredRules = computed(() => {
  if (!searchQuery.value.trim()) return localRules.value;
  const q = searchQuery.value.toLowerCase();
  return localRules.value.filter(r =>
    r.pattern.toLowerCase().includes(q) ||
    r.replacement.toLowerCase().includes(q) ||
    (r.description ?? '').toLowerCase().includes(q)
  );
});

watch([localRules, searchQuery], () => {
  const q = searchQuery.value.trim().toLowerCase();
  if (!q) {
    suggestions.value = [];
    return;
  }

  const allValues = [
    ...localRules.value.map(r => r.pattern.trim()),
    ...localRules.value.map(r => r.replacement.trim()),
    ...localRules.value.map(r => (r.description ?? '').trim()),
  ].filter(Boolean);

  suggestions.value = Array.from(new Set(allValues)).filter(v => v.toLowerCase().includes(q));
});

function onSearchInput(event: Event) {
  const value = (event.target as HTMLInputElement).value;
  searchQuery.value = value;
  showSuggestions.value = !!value.trim();
}

function applySuggestion(suggestion: string) {
  searchQuery.value = suggestion;
  showSuggestions.value = false;
}

function toggleHelpPanel() {
  showHelpPanel.value = !showHelpPanel.value;
}

const toasts = ref<Toast[]>([]);
let toastCounter = 0;

function showToast(message: string, type: Toast['type'] = 'success') {
  const id = ++toastCounter;
  toasts.value.push({ id, message, type });
  setTimeout(() => {
    toasts.value = toasts.value.filter(t => t.id !== id);
  }, 3500);
}

function toastIconClass(type: Toast['type']): string {
  if (type === 'success') return 'codicon-check';
  if (type === 'warning') return 'codicon-warning';
  return 'codicon-error';
}

type RuleField = keyof RuleRow;
function normalizeRule(input: Partial<RuleRow>): RuleRow {
  return {
    id: String(input.id ?? generateId()),
    pattern: String(input.pattern ?? ''),
    replacement: String(input.replacement ?? ''),
    type: (input.type as RuleRow['type']) ?? 'custom',
    enabled: input.enabled ?? true,
    description: input.description ? String(input.description) : '',
  };
}

watch(
  () => props.rules,
  newRules => {
    const incoming: RuleRow[] = (newRules || []).map(r => normalizeRule(r));

    if (localRules.value.length === 0) {
      localRules.value = incoming;
      return;
    }

    const incomingMap = new Map(incoming.map(r => [r.id, r]));

    const merged: RuleRow[] = localRules.value.map(local => {
      if (dirtyIds.value.has(local.id)) return local;
      return incomingMap.get(local.id) ?? local;
    });

    for (const inc of incoming) {
      if (!merged.find(r => r.id === inc.id)) {
        merged.push(inc);
      }
    }

    localRules.value = merged;
  },
  { immediate: true, deep: true }
);

watch(
  () => props.pendingScannedRules,
  scanned => {
    if (!scanned || scanned.length === 0) return;

    const existingPatterns = new Set(localRules.value.map(r => r.pattern.trim()));

    let addedCount = 0;
    for (const sr of scanned) {
      if (existingPatterns.has(sr.pattern.trim())) continue;
      existingPatterns.add(sr.pattern.trim());
      const newRule: RuleRow = normalizeRule(sr);
      localRules.value.push(newRule);
      dirtyIds.value = new Set([...dirtyIds.value, newRule.id]);
      addedCount++;
    }

    if (addedCount > 0) {
      showToast(`${addedCount} pattern${addedCount !== 1 ? 's' : ''} added from scan. Save to keep.`);
    } else {
      showToast('All scanned patterns already exist.', 'error');
    }

    emit('scannedRulesConsumed');
  },
  { deep: true }
);

watch(
  () => props.pendingImportedRules,
  imported => {
    if (!imported || imported.length === 0) return;

    const existingPatterns = new Set(localRules.value.map(r => r.pattern.trim()));
    let addedCount = 0;

    for (const incoming of imported) {
      if (existingPatterns.has(incoming.pattern.trim())) continue;
      existingPatterns.add(incoming.pattern.trim());
      const newRule: RuleRow = normalizeRule(incoming);
      localRules.value.push(newRule);
      dirtyIds.value = new Set([...dirtyIds.value, newRule.id]);
      addedCount++;
    }

    if (addedCount > 0) {
      showToast(`${addedCount} imported rule${addedCount !== 1 ? 's' : ''} added. Save to keep.`);
    } else {
      showToast('Imported rules are already present.', 'error');
    }

    emit('importedRulesConsumed');
  },
  { deep: true }
);

watch(
  () => props.validationFeedback,
  feedback => {
    if (!feedback || !Array.isArray(feedback.messages) || feedback.messages.length === 0) return;
    const toastType: Toast['type'] = feedback.level === 'warning' ? 'warning' : 'error';
    for (const msg of feedback.messages.slice(0, 4)) {
      showToast(msg, toastType);
    }
  },
  { deep: true }
);

watch(
  () => props.saveAck,
  ack => {
    if (!ack) return;

    if (ack.ruleIds.length === 0) {
      return;
    }

    const next = new Set(dirtyIds.value);
    let clearedCount = 0;
    for (const id of ack.ruleIds) {
      if (next.delete(id)) {
        clearedCount++;
      }
    }
    dirtyIds.value = next;

    if (clearedCount > 0) {
      showToast(`${clearedCount} rule${clearedCount !== 1 ? 's' : ''} saved.`);
    }
  },
  { deep: true }
);

function generateId(): string {
  return `rule_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

function addRule() {
  const newRule: RuleRow = {
    id: generateId(),
    pattern: '',
    replacement: '',
    type: 'custom',
    enabled: true,
    description: '',
  };
  localRules.value.push(newRule);
  dirtyIds.value = new Set([...dirtyIds.value, newRule.id]);
}

function requestRemoveRule(ruleId: string) {
  const rule = localRules.value.find(r => r.id === ruleId);
  if (rule) {
    ruleToDelete.value = rule;
  }
}

function confirmRemoveRule() {
  if (!ruleToDelete.value) return;

  const id = ruleToDelete.value.id;
  const removeIndex = localRules.value.findIndex(r => r.id === id);
  if (removeIndex !== -1) {
    localRules.value.splice(removeIndex, 1);
  }

  const next = new Set(dirtyIds.value);
  next.delete(id);
  dirtyIds.value = next;
  ruleToDelete.value = null;
  emit('deleteRule', id);
}

function cancelRemoveRule() {
  ruleToDelete.value = null;
}

function updateRule(ruleId: string, field: RuleField, value: RuleRow[RuleField]) {
  const target = localRules.value.find(r => r.id === ruleId);
  if (!target) return;

  target[field] = value as never;
  dirtyIds.value = new Set([...dirtyIds.value, target.id]);
}

function saveSingleRule(ruleId: string) {
  const rule = localRules.value.find(r => r.id === ruleId);
  if (!rule || (rule.pattern.trim() === '' && rule.replacement.trim() === '')) return;

  if (!rule.pattern.trim()) {
    showToast('Pattern is required before saving.', 'error');
    return;
  }

  if (!rule.replacement.trim()) {
    showToast('Replacement is required before saving.', 'error');
    return;
  }

  emit('saveSingleRule', {
    ...rule,
    pattern: rule.pattern.trim(),
    replacement: rule.replacement.trim(),
  });
}

function confirmRules() {
  const validRules = localRules.value
    .filter(r => r.pattern.trim() !== '' || r.replacement.trim() !== '')
    .map(r => ({
      ...r,
      pattern: r.pattern.trim(),
      replacement: r.replacement.trim(),
      description: (r.description ?? '').trim(),
    }));

  for (const rule of validRules) {
    if (!rule.pattern) {
      showToast('Cannot save: one or more rules are missing a pattern.', 'error');
      return;
    }
    if (!rule.replacement) {
      showToast('Cannot save: one or more rules are missing a replacement.', 'error');
      return;
    }
  }

  localRules.value = validRules;

  emit('saveRules', validRules);
}

function exportRules() {
  const validRules = localRules.value
    .filter(r => r.pattern.trim() !== '' || r.replacement.trim() !== '')
    .map(r => ({
      ...r,
      pattern: r.pattern.trim(),
      replacement: r.replacement.trim(),
      description: (r.description ?? '').trim(),
    }));
  emit('exportRules', validRules);
}
</script>

<style scoped>
.rule-editor-container {
  display: flex;
  flex-direction: column;
  flex: 1;
  min-height: 0;
  overflow: hidden;
  position: relative;
}

.search-bar-wrapper {
  position: relative;
  padding: 12px 20px 8px;
  border-bottom: 1px solid var(--vscode-editorGroup-border);
  background-color: var(--vscode-editor-background);
}

.search-toolbar {
  display: flex;
  align-items: center;
  gap: 10px;
}

.search-bar {
  width: 100%;
  flex: 1;
}

.help-toggle {
  flex-shrink: 0;
}

.autocomplete-list {
  position: absolute;
  left: 20px;
  right: 20px;
  top: 46px;
  margin: 0;
  padding: 4px 0;
  list-style: none;
  max-height: 180px;
  overflow-y: auto;
  border: 1px solid var(--vscode-editorWidget-border);
  background-color: var(--vscode-editorWidget-background);
  z-index: 20;
}

.help-panel {
  padding: 12px 20px 14px;
  border-bottom: 1px solid var(--vscode-editorGroup-border);
  background:
    linear-gradient(135deg, color-mix(in srgb, var(--vscode-editorWidget-background) 88%, transparent), transparent),
    var(--vscode-sideBar-background, var(--vscode-editor-background));
}

.help-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 12px;
}

.help-card {
  border: 1px solid var(--vscode-editorWidget-border, var(--vscode-editorGroup-border));
  border-radius: 10px;
  padding: 12px;
  background: color-mix(in srgb, var(--vscode-editor-background) 86%, transparent);
  box-shadow: 0 8px 24px -18px rgba(0, 0, 0, 0.45);
}

.help-title {
  margin: 0 0 10px;
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: var(--vscode-descriptionForeground);
}

.help-entry + .help-entry {
  margin-top: 10px;
  padding-top: 10px;
  border-top: 1px solid var(--vscode-editorGroup-border);
}

.help-entry-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin-bottom: 4px;
}

.help-entry p {
  margin: 0;
  color: var(--vscode-descriptionForeground);
  line-height: 1.45;
  font-size: 12px;
}

.shortcut {
  font: inherit;
  font-size: 11px;
  padding: 2px 8px;
  border-radius: 999px;
  border: 1px solid var(--vscode-editorWidget-border, var(--vscode-editorGroup-border));
  background: var(--vscode-badge-background);
  color: var(--vscode-badge-foreground);
  white-space: nowrap;
}

.autocomplete-item {
  padding: 6px 10px;
  cursor: pointer;
  color: var(--vscode-editor-foreground);
}

.autocomplete-item:hover {
  background-color: var(--vscode-list-hoverBackground);
}

.rules-grid-wrapper {
  flex: 1;
  overflow-y: auto;
  overflow-x: hidden;
  scrollbar-width: thin;
  scrollbar-color: var(--vscode-scrollbarSlider-background) transparent;
}

.grid-header,
.grid-row {
  display: grid;
  grid-template-columns: 1.1fr 1fr 0.65fr 0.45fr 1fr 96px;
  align-items: center;
}

.grid-header {
  padding: 6px 20px;
  background-color: var(--vscode-editorGroupHeader-tabsBackground);
  border-bottom: 1px solid var(--vscode-editorGroup-border);
  font-size: 10.5px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--vscode-descriptionForeground);
  position: sticky;
  top: 0;
  z-index: 2;
}

.grid-body {
  display: flex;
  flex-direction: column;
}

.grid-row {
  position: relative;
  padding: 5px 20px;
  border-bottom: 1px solid var(--vscode-editorGroup-border);
  gap: 8px;
  transition: background-color 0.15s ease;
}

.grid-row:last-child {
  border-bottom: none;
}

.grid-row:hover {
  background-color: var(--vscode-list-hoverBackground);
}

.dirty-bar {
  position: absolute;
  left: 0;
  top: 0;
  bottom: 0;
  width: 3px;
  border-radius: 0 2px 2px 0;
  background-color: var(--vscode-inputValidation-warningBorder, #cca700);
  pointer-events: none;
}

.row-dirty {
  background-color: var(--vscode-inputValidation-warningBackground, rgba(204, 167, 0, 0.04));
}

.col-pattern,
.col-replacement,
.col-description {
  min-width: 0;
}

.col-enabled {
  display: flex;
  justify-content: center;
}

.checkbox-wrap {
  display: inline-flex;
  align-items: center;
  justify-content: center;
}

.rule-select {
  width: 100%;
  height: 28px;
  background-color: var(--vscode-input-background);
  color: var(--vscode-input-foreground);
  border: 1px solid var(--vscode-input-border, var(--vscode-editorGroup-border));
  border-radius: 4px;
  padding: 0 8px;
  outline: none;
}

.rule-select:focus {
  border-color: var(--vscode-focusBorder);
}

.col-actions {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 2px;
}

.field-full {
  width: 100%;
  display: block;
}

.btn-danger::part(control) {
  color: var(--vscode-errorForeground);
  opacity: 0.75;
  transition: opacity 0.15s ease;
}

.btn-danger:hover::part(control) {
  opacity: 1;
}

.footer-actions {
  flex-shrink: 0;
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
  padding: 10px 20px;
  border-top: 1px solid var(--vscode-editorGroup-border);
  background-color: var(--vscode-editor-background);
  box-shadow: 0 -2px 8px -2px rgba(0, 0, 0, 0.15);
}

.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 48px 24px;
  gap: 8px;
  text-align: center;
  color: var(--vscode-descriptionForeground);
}

.empty-state .codicon {
  font-size: 32px;
  opacity: 0.35;
  margin-bottom: 4px;
}

.empty-title {
  margin: 0;
  font-size: 13px;
  font-weight: 600;
  color: var(--vscode-editor-foreground);
  opacity: 0.7;
}

.empty-sub {
  margin: 0;
  font-size: 12px;
  opacity: 0.55;
  max-width: 260px;
  line-height: 1.5;
}

.toast-region {
  position: fixed;
  bottom: 56px;
  right: 16px;
  display: flex;
  flex-direction: column;
  gap: 6px;
  z-index: 300;
  pointer-events: none;
}

.toast {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 14px;
  border-radius: 5px;
  font-size: 12px;
  font-weight: 500;
  backdrop-filter: blur(6px);
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.25);
  pointer-events: auto;
}

.toast--success {
  background-color: var(--vscode-statusBar-background);
  color: var(--vscode-statusBar-foreground);
  border: 1px solid var(--vscode-statusBar-border, transparent);
}

.toast--error {
  background-color: var(--vscode-inputValidation-errorBackground);
  color: var(--vscode-inputValidation-errorForeground, var(--vscode-errorForeground));
  border: 1px solid var(--vscode-inputValidation-errorBorder);
}

.toast--warning {
  background-color: var(--vscode-inputValidation-warningBackground, rgba(204, 167, 0, 0.08));
  color: var(--vscode-editor-foreground);
  border: 1px solid var(--vscode-inputValidation-warningBorder, #cca700);
}

.dialog-overlay {
  position: fixed;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  background-color: rgba(0, 0, 0, 0.45);
  backdrop-filter: blur(4px);
  z-index: 200;
}

.dialog-content {
  background-color: var(--vscode-editor-background);
  color: var(--vscode-editor-foreground);
  padding: 24px 24px 20px;
  border-radius: 8px;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.35);
  width: 90%;
  max-width: 380px;
  border: 1px solid var(--vscode-editorGroup-border);
}

.dialog-icon {
  font-size: 22px;
  color: var(--vscode-inputValidation-warningBorder, #cca700);
  margin-bottom: 10px;
}

.dialog-title {
  font-size: 15px;
  font-weight: 700;
  margin: 0 0 10px;
}

.dialog-description {
  margin: 0 0 22px;
  font-size: 13px;
  color: var(--vscode-descriptionForeground);
  line-height: 1.5;
}

.pattern-preview {
  font-family: var(--vscode-editor-font-family, monospace);
  font-size: 11px;
  background-color: var(--vscode-textCodeBlock-background);
  padding: 1px 5px;
  border-radius: 3px;
}

.dialog-actions {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
}

.btn-delete-confirm::part(control) {
  background-color: var(--vscode-errorForeground);
  color: #fff;
}

.rule-row-enter-active {
  transition: opacity 0.2s ease, transform 0.2s ease;
}

.rule-row-leave-active {
  transition: opacity 0.18s ease, transform 0.18s ease;
  position: absolute;
  width: 100%;
}

.rule-row-enter-from {
  opacity: 0;
  transform: translateY(-6px);
}

.rule-row-leave-to {
  opacity: 0;
  transform: translateX(16px);
}

.rule-row-move {
  transition: transform 0.2s ease;
}

.toast-enter-active {
  transition: opacity 0.25s ease, transform 0.25s ease;
}

.toast-leave-active {
  transition: opacity 0.2s ease, transform 0.2s ease;
}

.toast-enter-from {
  opacity: 0;
  transform: translateY(8px) scale(0.96);
}

.toast-leave-to {
  opacity: 0;
  transform: translateX(12px) scale(0.96);
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.2s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}

.dialog-enter-active {
  transition: opacity 0.2s ease;
}

.dialog-leave-active {
  transition: opacity 0.18s ease;
}

.dialog-enter-from,
.dialog-leave-to {
  opacity: 0;
}

.dialog-enter-from .dialog-content,
.dialog-leave-to .dialog-content {
  transform: scale(0.97) translateY(-6px);
}

.dialog-enter-active .dialog-content,
.dialog-leave-active .dialog-content {
  transition: transform 0.2s ease;
}

@media (max-width: 960px) {
  .search-toolbar {
    flex-direction: column;
    align-items: stretch;
  }

  .help-toggle {
    width: 100%;
  }
}
</style>
