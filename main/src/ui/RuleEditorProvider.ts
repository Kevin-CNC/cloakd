import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { ConfigManager } from '../utils/ConfigManager';

export class RuleEditorProvider implements vscode.WebviewViewProvider {
    public static readonly viewType = 'prompthider.rulesView';
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
                    const incomingRules = message.rules as any[];
                    const diskConfig = await this._configManager.loadFullConfig();
                    let updatedRules = Array.isArray(diskConfig?.rules) ? diskConfig.rules.map((diskRule: any) => {
                        const incoming = incomingRules.find((r: any) => r.id === diskRule.id);
                        if (!incoming) return diskRule;
                        return {
                            ...diskRule,
                            pattern: incoming.pattern,
                            replacement: incoming.replacement,
                            type: incoming.type,
                            enabled: incoming.enabled,
                            description: incoming.description,
                        };
                    }) : [];
                    // Add any new rules
                    for (const incoming of incomingRules) {
                        if (!updatedRules.find((r: any) => r.id === incoming.id)) {
                            updatedRules.push(incoming);
                        }
                    }
                    await this._configManager.saveProjectRules(updatedRules);
                    this._onConfigChanged?.();
                    webviewView.webview.postMessage({ command: 'rulesSaved', ruleIds: updatedRules.map((r: any) => r.id) });
                    break;
                }

                case 'saveSingleRule': {
                    const ruleCarried = message.rule;
                    const loadedProject = await this._configManager.loadFullConfig();
                    const currentRules = Array.isArray(loadedProject?.rules) ? loadedProject.rules : [];
                    const ruleExistsIndx = currentRules.findIndex((r: any) => r.id === ruleCarried.id);
                    if (ruleExistsIndx !== -1) {
                        currentRules[ruleExistsIndx] = {
                            ...currentRules[ruleExistsIndx],
                            pattern: ruleCarried.pattern,
                            replacement: ruleCarried.replacement,
                            type: ruleCarried.type,
                            enabled: ruleCarried.enabled,
                            description: ruleCarried.description,
                        };
                    } else {
                        currentRules.push(ruleCarried);
                    }
                    await this._configManager.saveProjectRules(currentRules);
                    this._onConfigChanged?.();
                    webviewView.webview.postMessage({ command: 'rulesSaved', ruleIds: [ruleCarried.id] });
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
                    vscode.commands.executeCommand('prompthider.scanIacFile');
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

    // normalizeRules is no longer needed

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
                type: r.type,
                enabled: r.enabled,
                description: r.description,
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
                    type: ['ip', 'email', 'uuid', 'secret', 'api-key', 'path', 'jwt', 'private-key', 'custom'].includes(String(r.type))
                        ? String(r.type)
                        : 'custom',
                    enabled: r.enabled !== undefined ? Boolean(r.enabled) : true,
                    description: r.description ? String(r.description) : '',
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
                    type: String(r.type ?? 'custom'),
                    enabled: Boolean(r.enabled ?? true),
                    description: r.description ? String(r.description) : '',
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
