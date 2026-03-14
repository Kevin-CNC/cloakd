import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { ConfigManager } from '../utils/ConfigManager';
import { validateRules } from '../anonymizer/RuleValidator';
import {
    exportableRules,
    normalizeImportedRules,
    normalizeRuleForStorage,
    toWebviewRule
} from '../utils/RuleMetadata';
import { type ToolWrappingPolicyConfig } from '../tools/ToolPolicy';
import { CloakdLogger } from '../utils/CloakdLogger';

type DynamicWrappingMode = 'strict' | 'balanced' | 'trustedLocal';

interface DynamicToolWrappingMessage {
    enabled: boolean;
    mode: DynamicWrappingMode;
    policies: unknown;
}

export class mainUIProvider {
    private static currentPanel: vscode.WebviewPanel | undefined;
    private static onConfigChanged?: () => void;
    private static activeConfigManager?: ConfigManager;
    private static isWebviewReady = false;
    private static pendingMessages: unknown[] = [];

    private static flushPendingMessages(): void {
        if (!mainUIProvider.currentPanel || !mainUIProvider.isWebviewReady || mainUIProvider.pendingMessages.length === 0) {
            return;
        }

        const messages = [...mainUIProvider.pendingMessages];
        mainUIProvider.pendingMessages = [];

        for (const message of messages) {
            mainUIProvider.currentPanel.webview.postMessage(message);
        }
    }

    /**
     * Post an arbitrary message to the webview, if it exists.
     * Used by commands (e.g. IaC scan) to push data into the Vue app.
     */
    public static postMessage(message: unknown): void {
        if (mainUIProvider.currentPanel && mainUIProvider.isWebviewReady) {
            mainUIProvider.currentPanel.webview.postMessage(message);
            return;
        }

        mainUIProvider.pendingMessages.push(message);
    }

    static refreshRules(){
        this.postMessage({command: 'refreshRules'})
    }

    public static isPanelOpen(): boolean {
        return !!mainUIProvider.currentPanel;
    }

    public static refreshCurrentPanel(): void {
        if (mainUIProvider.currentPanel && mainUIProvider.activeConfigManager) {
            void mainUIProvider.postInit(mainUIProvider.currentPanel.webview, mainUIProvider.activeConfigManager);
        }
    }

    public static show(context: vscode.ExtensionContext, configManager?: ConfigManager, onConfigChanged?: () => void) {
        if (onConfigChanged) {
            mainUIProvider.onConfigChanged = onConfigChanged;
        }

        if (configManager) {
            mainUIProvider.activeConfigManager = configManager;
        }

        // If a panel already exists, just reveal it
        if (mainUIProvider.currentPanel) {
            mainUIProvider.currentPanel.reveal(vscode.ViewColumn.One);
            if (mainUIProvider.activeConfigManager) {
                void mainUIProvider.postInit(mainUIProvider.currentPanel.webview, mainUIProvider.activeConfigManager);
            }
            return;
        }

        const panel = vscode.window.createWebviewPanel(
            'Cloakd',
            'Prompt Hider: Main',
            vscode.ViewColumn.One,
            {
                enableScripts: true,
                localResourceRoots: [
                    vscode.Uri.file(path.join(context.extensionPath, 'dist', 'webview')),
                    vscode.Uri.file(path.join(context.extensionPath, 'node_modules', '@vscode', 'codicons', 'dist'))
                ]
            }
        );

        mainUIProvider.currentPanel = panel;
        mainUIProvider.isWebviewReady = false;

        panel.onDidDispose(() => {
            mainUIProvider.currentPanel = undefined;
            mainUIProvider.isWebviewReady = false;
        });

        // ---- Handle messages from the webview ---- ////
        panel.webview.onDidReceiveMessage(async (message) => {
            switch (message.command) {
                case 'ready': {
                    if (!mainUIProvider.activeConfigManager) { break; }
                    await mainUIProvider.postInit(panel.webview, mainUIProvider.activeConfigManager);
                    mainUIProvider.isWebviewReady = true;
                    mainUIProvider.flushPendingMessages();
                    break;
                }

                case 'saveRules': {
                    const activeConfig = mainUIProvider.activeConfigManager;
                    if (!activeConfig) { break; }
                    const incomingRules = message.rules as any[];
                    const diskConfig = await activeConfig.loadFullConfig();
                    const diskRules = Array.isArray(diskConfig?.rules) ? diskConfig.rules : [];
                    let updatedRules = diskRules.map((diskRule: any) => {
                        const incoming = incomingRules.find((r: any) => r.id === diskRule.id);
                        if (!incoming) return diskRule;
                        return normalizeRuleForStorage(incoming, diskRule);
                    });
                    // Add any new rules
                    for (const incoming of incomingRules) {
                        if (!updatedRules.find((r: any) => r.id === incoming.id)) {
                            updatedRules.push(normalizeRuleForStorage(incoming));
                        }
                    }
                    const validation = validateRules(updatedRules);
                    if (!validation.valid) {
                        panel.webview.postMessage({
                            command: 'ruleValidation',
                            level: 'error',
                            source: 'saveRules',
                            messages: validation.errors,
                        });
                        vscode.window.showErrorMessage('Rule validation failed. Fix invalid regex or replacement values before saving.');
                        break;
                    }
                    if (validation.warnings.length > 0) {
                        panel.webview.postMessage({
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
                            break;
                        }
                    }
                    await activeConfig.saveProjectRules(updatedRules);
                    mainUIProvider.onConfigChanged?.();
                    panel.webview.postMessage({ command: 'rulesSaved', ruleIds: updatedRules.map((r: any) => r.id) });
                    break;
                }

                case 'saveSingleRule': {
                    const activeConfig = mainUIProvider.activeConfigManager;
                    if (!activeConfig) { break; }
                    const ruleCarried = message.rule;
                    const loadedProject = await activeConfig.loadFullConfig();
                    const currentRules = Array.isArray(loadedProject?.rules) ? loadedProject.rules : [];
                    const ruleExistsIndx = currentRules.findIndex((r: any) => r.id === ruleCarried.id);
                    if (ruleExistsIndx !== -1) {
                        currentRules[ruleExistsIndx] = normalizeRuleForStorage(
                            ruleCarried,
                            currentRules[ruleExistsIndx]
                        );
                    } else {
                        currentRules.push(normalizeRuleForStorage(ruleCarried));
                    }
                    const validation = validateRules(currentRules);
                    if (!validation.valid) {
                        panel.webview.postMessage({
                            command: 'ruleValidation',
                            level: 'error',
                            source: 'saveSingleRule',
                            messages: validation.errors,
                        });
                        vscode.window.showErrorMessage('Rule validation failed. Fix invalid regex or replacement values before saving.');
                        break;
                    }
                    if (validation.warnings.length > 0) {
                        panel.webview.postMessage({
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
                            break;
                        }
                    }
                    await activeConfig.saveProjectRules(currentRules);
                    mainUIProvider.onConfigChanged?.();
                    panel.webview.postMessage({ command: 'rulesSaved', ruleIds: [ruleCarried.id] });
                    break;
                }

                case 'deleteRule': {
                    const activeConfig = mainUIProvider.activeConfigManager;
                    if (!activeConfig) { break; }
                    const ruleIdToDelete = message.id as string;
                    const loadedProject = await activeConfig.loadFullConfig();
                    const currentRules = Array.isArray(loadedProject?.rules) ? loadedProject.rules : [];
                    const updatedRules = currentRules.filter((r: any) => r.id !== ruleIdToDelete);

                    await activeConfig.saveProjectRules(updatedRules);
                    mainUIProvider.onConfigChanged?.();
                    panel.webview.postMessage({ command: 'ruleDeleted' });
                    break;
                }

                case 'importRules': {
                    await mainUIProvider.importRulesToWebview(panel.webview);
                    break;
                }

                case 'exportRules': {
                    const activeConfig = mainUIProvider.activeConfigManager;
                    if (!activeConfig) { break; }
                    await mainUIProvider.exportRulesFromWebview(activeConfig, message.rules as any[]);
                    break;
                }

                case 'scanCurrentFile': {
                    vscode.commands.executeCommand('cloakd.scanCurrentFile');
                    break;
                }

                case 'scanIacFile': {
                    // Delegate to the registered command which handles the file picker + scanning
                    vscode.commands.executeCommand('cloakd.scanIacFile');
                    break;
                }

                case 'scanSecrets': {
                    vscode.commands.executeCommand('cloakd.scanSecrets');
                    break;
                }

                case 'saveToolWrappingConfig': {
                    const activeConfig = mainUIProvider.activeConfigManager;
                    if (!activeConfig) { break; }

                    try {
                        const payload = message as DynamicToolWrappingMessage;
                        const scopeUri = vscode.workspace.getWorkspaceFolder(
                            vscode.Uri.file(activeConfig.getConfigFilePath())
                        )?.uri;

                        const mode = payload.mode === 'balanced' || payload.mode === 'trustedLocal' || payload.mode === 'strict'
                            ? payload.mode
                            : 'strict';
                        const policies = payload.policies && typeof payload.policies === 'object' && !Array.isArray(payload.policies)
                            ? payload.policies
                            : {};

                        await activeConfig.saveDynamicToolWrappingEnabled(
                            Boolean(payload.enabled),
                            scopeUri,
                            vscode.ConfigurationTarget.Workspace
                        );
                        await activeConfig.saveDynamicToolWrappingMode(
                            mode,
                            scopeUri,
                            vscode.ConfigurationTarget.Workspace
                        );
                        await activeConfig.saveDynamicToolWrappingPolicies(
                            policies as ToolWrappingPolicyConfig,
                            scopeUri,
                            vscode.ConfigurationTarget.Workspace
                        );

                        panel.webview.postMessage({
                            command: 'toolWrappingSaved',
                            dynamicToolWrapping: {
                                enabled: Boolean(payload.enabled),
                                mode,
                                policies,
                            },
                        });
                    } catch (error) {
                        const messageText = error instanceof Error ? error.message : String(error);
                        CloakdLogger.error('Failed to save wrapped tool trust policy settings.', {
                            reason: messageText,
                        });

                        panel.webview.postMessage({
                            command: 'toolWrappingSaveFailed',
                            message: messageText,
                        });
                    }
                    break;
                }
            }
        });

        // ---- Load the built Vue app ----
        try {
            const distPath = path.join(context.extensionPath, 'dist', 'webview', 'index.html');

            if (!fs.existsSync(distPath)) {
                vscode.window.showErrorMessage(
                    `Webview assets not found at ${distPath}. Run 'npm run webview:build' first.`
                );
                panel.dispose();
                return;
            }

            let html = fs.readFileSync(distPath, 'utf8');

            // Get URI for codicon stylesheet
            const codiconsUri = panel.webview.asWebviewUri(
                vscode.Uri.file(path.join(context.extensionPath, 'node_modules', '@vscode', 'codicons', 'dist', 'codicon.css'))
            );

            // Add codicon stylesheet to the head
            html = html.replace('</head>', `<link href="${codiconsUri}" rel="stylesheet" /></head>`);

            // Transform asset URLs to use vscode-resource:// scheme
            const distDir = path.join(context.extensionPath, 'dist', 'webview');
            html = html.replace(/(?:src|href)="\/([^"]+)"/g, (match, file) => {
                const resourceUri = vscode.Uri.file(path.join(distDir, file));
                const webviewUri = panel.webview.asWebviewUri(resourceUri);
                const attrName = match.startsWith('src=') ? 'src' : 'href';
                return `${attrName}="${webviewUri}"`;
            });

            panel.webview.html = html;
        } catch (error) {
            vscode.window.showErrorMessage(`Failed to load webview: ${error instanceof Error ? error.message : 'Unknown error'}`);
            panel.dispose();
        }
    }

    // normalizeRules is no longer needed

    private static async postInit(webview: vscode.Webview, configManager: ConfigManager): Promise<void> {
        const config = await configManager.loadFullConfig();
        const name = configManager.getRulesheetName();
        const scopeUri = vscode.workspace.getWorkspaceFolder(vscode.Uri.file(configManager.getConfigFilePath()))?.uri;
        webview.postMessage({
            command: 'init',
            viewMode: 'main',
            rulesheetName: name,
            workspaceName: configManager.getWorkspaceFolderName(),
            rulesheetPath: configManager.getConfigFilePath(),
            rules: (config?.rules ?? []).map(r => toWebviewRule(r)),
            enabled: config?.enabled ?? false,
            dynamicToolWrapping: {
                enabled: configManager.getDynamicToolWrappingEnabled(scopeUri),
                mode: configManager.getDynamicToolWrappingMode(scopeUri),
                policies: configManager.loadDynamicToolWrappingPolicies(scopeUri),
            },
        });
    }

    private static async importRulesToWebview(webview: vscode.Webview): Promise<void> {
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
            const normalizedRules = normalizeImportedRules(sourceRules);

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

    private static async exportRulesFromWebview(configManager: ConfigManager, rules: any[]): Promise<void> {
        const saveUri = await vscode.window.showSaveDialog({
            saveLabel: 'Export Rules',
            filters: { 'JSON Files': ['json'] },
            defaultUri: vscode.Uri.file(`${configManager.getRulesheetName()}.rules.export.json`),
        });

        if (!saveUri) {
            return;
        }

        try {
            const normalizedRules = exportableRules(rules ?? []);

            fs.writeFileSync(saveUri.fsPath, JSON.stringify({
                version: 1,
                exportedAt: new Date().toISOString(),
                rulesheet: configManager.getRulesheetName(),
                rules: normalizedRules,
            }, null, 2), 'utf8');

            vscode.window.showInformationMessage(`Exported ${normalizedRules.length} rule(s) to ${path.basename(saveUri.fsPath)}.`);
        } catch (error) {
            vscode.window.showErrorMessage(`Failed to export rules: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
}
