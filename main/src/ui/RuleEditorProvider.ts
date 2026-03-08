import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { ConfigManager } from '../utils/ConfigManager';
import { validateRules } from '../anonymizer/RuleValidator';

export class RuleEditorProvider implements vscode.WebviewViewProvider {
    public static readonly viewType = 'cloakd.rulesView';
    private _view?: vscode.WebviewView;
    private _configManager: ConfigManager;

    constructor(
        private readonly _extensionUri: vscode.Uri,
        configManager: ConfigManager,
        private readonly _onConfigChanged?: () => void
    ) {
        this._configManager = configManager;
    }

    public setConfigManager(configManager: ConfigManager): void {
        this._configManager = configManager;
        if (this._view) {
            void this.postInit(this._view.webview);
        }
    }

    public async resolveWebviewView(
        webviewView: vscode.WebviewView,
        _context: vscode.WebviewViewResolveContext,
        _token: vscode.CancellationToken
    ) {
        this._view = webviewView;

        webviewView.webview.options = {
            enableScripts: true,
            localResourceRoots: [
                vscode.Uri.file(path.join(this._extensionUri.fsPath, 'dist', 'webview')),
                vscode.Uri.file(path.join(this._extensionUri.fsPath, 'node_modules', '@vscode', 'codicons', 'dist')),
                this._extensionUri,
            ]
        };

        webviewView.webview.onDidReceiveMessage(async (message) => {
            switch (message.command) {
                case 'ready': {
                    await this.postInit(webviewView.webview);
                    break;
                }

                case 'saveRules': {
                    const rules = this.normalizeRules(message.rules as any[]);
                    const validation = validateRules(rules);
                    if (!validation.valid) {
                        webviewView.webview.postMessage({
                            command: 'ruleValidation',
                            level: 'error',
                            source: 'saveRules',
                            messages: validation.errors,
                        });
                        vscode.window.showErrorMessage('Rule validation failed. Fix invalid regex or replacement values before saving.');
                        return;
                    }

                    if (validation.warnings.length > 0) {
                        webviewView.webview.postMessage({
                            command: 'ruleValidation',
                            level: 'warning',
                            source: 'saveRules',
                            messages: validation.warnings,
                        });
                        const answer = await vscode.window.showWarningMessage(
                            `Rule warnings detected (${validation.warnings.length}). Save anyway?`,
                            { modal: true },
                            'Save Anyway',
                            'Cancel'
                        );

                        if (answer !== 'Save Anyway') {
                            return;
                        }
                    }

                    await this._configManager.saveProjectRules(rules);
                    this._onConfigChanged?.();
                    webviewView.webview.postMessage({ command: 'rulesSaved' });
                    break;
                }

                case 'saveSingleRule': {
                    const ruleCarried = message.rule as { id: string; pattern: string; replacement: string };
                    const loadedProject = await this._configManager.loadFullConfig();
                    const currentRules = Array.isArray(loadedProject?.rules) ? loadedProject.rules : [];
                    const ruleExistsIndx = currentRules.findIndex(r => r.id === ruleCarried.id);
                    const normalizedRule = {
                        id: ruleCarried.id,
                        type: 'custom' as const,
                        pattern: ruleCarried.pattern,
                        replacement: ruleCarried.replacement,
                        enabled: true,
                        description: `Custom rule: ${ruleCarried.pattern} → ${ruleCarried.replacement}`,
                    };

                    if (ruleExistsIndx !== -1) {
                        currentRules[ruleExistsIndx] = normalizedRule;
                    } else {
                        currentRules.push(normalizedRule);
                    }

                    const validation = validateRules(currentRules);
                    if (!validation.valid) {
                        webviewView.webview.postMessage({
                            command: 'ruleValidation',
                            level: 'error',
                            source: 'saveSingleRule',
                            messages: validation.errors,
                        });
                        vscode.window.showErrorMessage('Rule validation failed. Fix invalid regex or replacement values before saving.');
                        return;
                    }

                    if (validation.warnings.length > 0) {
                        webviewView.webview.postMessage({
                            command: 'ruleValidation',
                            level: 'warning',
                            source: 'saveSingleRule',
                            messages: validation.warnings,
                        });
                        const answer = await vscode.window.showWarningMessage(
                            `Rule warnings detected (${validation.warnings.length}). Save anyway?`,
                            { modal: true },
                            'Save Anyway',
                            'Cancel'
                        );

                        if (answer !== 'Save Anyway') {
                            return;
                        }
                    }

                    await this._configManager.saveProjectRules(currentRules);
                    this._onConfigChanged?.();
                    webviewView.webview.postMessage({ command: 'rulesSaved' });
                    break;
                }

                case 'deleteRule': {
                    const ruleIdToDelete = message.id as string;
                    const loadedProject = await this._configManager.loadFullConfig();
                    const currentRules = Array.isArray(loadedProject?.rules) ? loadedProject.rules : [];
                    const updatedRules = currentRules.filter(r => r.id !== ruleIdToDelete);

                    await this._configManager.saveProjectRules(updatedRules);
                    this._onConfigChanged?.();
                    webviewView.webview.postMessage({ command: 'ruleDeleted' });
                    break;
                }

                case 'scanIacFile': {
                    vscode.commands.executeCommand('cloakd.scanIacFile');
                    break;
                }

                case 'importRules': {
                    await this.importRulesToWebview(webviewView.webview);
                    break;
                }

                case 'exportRules': {
                    await this.exportRulesFromWebview(message.rules as any[]);
                    break;
                }
            }
        });

        webviewView.webview.html = this._getHtmlForWebview(webviewView.webview);
    }

    private _getHtmlForWebview(webview: vscode.Webview) {
        const distPath = path.join(this._extensionUri.fsPath, 'dist', 'webview', 'index.html');
        if (!fs.existsSync(distPath)) {
            return `<!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Prompt Hider</title>
            </head>
            <body>
                <h3>Prompt Hider</h3>
                <p>Webview assets were not found. Run <code>npm run webview:build</code> and then <code>npm run compile</code>.</p>
            </body>
            </html>`;
        }

        let html = fs.readFileSync(distPath, 'utf8');
        const codiconsUri = webview.asWebviewUri(
            vscode.Uri.file(path.join(this._extensionUri.fsPath, 'node_modules', '@vscode', 'codicons', 'dist', 'codicon.css'))
        );
        html = html.replace('</head>', `<link href="${codiconsUri}" rel="stylesheet" /></head>`);

        const distDir = path.join(this._extensionUri.fsPath, 'dist', 'webview');
        html = html.replace(/(?:src|href)="\/([^"]+)"/g, (match, file) => {
            const resourceUri = vscode.Uri.file(path.join(distDir, file));
            const webviewUri = webview.asWebviewUri(resourceUri);
            const attrName = match.startsWith('src=') ? 'src' : 'href';
            return `${attrName}="${webviewUri}"`;
        });

        return html;
    }

    private normalizeRules(rules: any[]) {
        return (rules ?? []).map(r => ({
            id: String(r.id),
            type: 'custom' as const,
            pattern: String(r.pattern ?? ''),
            replacement: String(r.replacement ?? ''),
            enabled: true,
            description: `Custom rule: ${String(r.pattern ?? '')} → ${String(r.replacement ?? '')}`,
        }));
    }

    private async postInit(webview: vscode.Webview): Promise<void> {
        const config = await this._configManager.loadFullConfig();
        const name = this._configManager.getRulesheetName();
        webview.postMessage({
            command: 'init',
            rulesheetName: name,
            workspaceName: this._configManager.getWorkspaceFolderName(),
            rulesheetPath: this._configManager.getConfigFilePath(),
            rules: (config?.rules ?? []).map(r => ({
                id: r.id,
                pattern: typeof r.pattern === 'string' ? r.pattern : r.pattern.source,
                replacement: r.replacement,
            })),
            enabled: config?.enabled ?? false,
        });
    }

    private async importRulesToWebview(webview: vscode.Webview): Promise<void> {
        const picked = await vscode.window.showOpenDialog({
            canSelectMany: false,
            canSelectFiles: true,
            canSelectFolders: false,
            openLabel: 'Import Rules',
            filters: {
                'JSON Files': ['json'],
                'All Files': ['*'],
            },
        });

        if (!picked || picked.length === 0) {
            return;
        }

        try {
            const content = fs.readFileSync(picked[0].fsPath, 'utf8');
            const parsed = JSON.parse(content) as any;
            const sourceRules = Array.isArray(parsed) ? parsed : Array.isArray(parsed.rules) ? parsed.rules : [];
            const normalizedRules = sourceRules
                .map((r: any) => ({
                    id: String(r.id ?? `rule_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`),
                    pattern: typeof r.pattern === 'string' ? r.pattern : String(r.pattern?.source ?? ''),
                    replacement: String(r.replacement ?? ''),
                }))
                .filter((r: { pattern: string; replacement: string }) => r.pattern.trim() !== '' || r.replacement.trim() !== '');

            webview.postMessage({
                command: 'importedRules',
                rules: normalizedRules,
                fileName: path.basename(picked[0].fsPath),
            });
            vscode.window.showInformationMessage(`Imported ${normalizedRules.length} rule(s) from ${path.basename(picked[0].fsPath)}.`);
        } catch (error) {
            vscode.window.showErrorMessage(`Failed to import rules: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }

    private async exportRulesFromWebview(rules: any[]): Promise<void> {
        const saveUri = await vscode.window.showSaveDialog({
            saveLabel: 'Export Rules',
            filters: { 'JSON Files': ['json'] },
            defaultUri: vscode.Uri.file(`${this._configManager.getRulesheetName()}.rules.export.json`),
        });

        if (!saveUri) {
            return;
        }

        try {
            const normalizedRules = (rules ?? [])
                .map(r => ({
                    id: String(r.id),
                    pattern: String(r.pattern ?? ''),
                    replacement: String(r.replacement ?? ''),
                }))
                .filter((r: { pattern: string; replacement: string }) => r.pattern.trim() !== '' || r.replacement.trim() !== '');

            fs.writeFileSync(saveUri.fsPath, JSON.stringify({
                version: 1,
                exportedAt: new Date().toISOString(),
                rulesheet: this._configManager.getRulesheetName(),
                rules: normalizedRules,
            }, null, 2), 'utf8');

            vscode.window.showInformationMessage(`Exported ${normalizedRules.length} rule(s) to ${path.basename(saveUri.fsPath)}.`);
        } catch (error) {
            vscode.window.showErrorMessage(`Failed to export rules: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
}
