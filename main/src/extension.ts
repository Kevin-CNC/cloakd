import * as vscode from 'vscode';
import * as path from 'path';
import { AnonymizationEngine } from './anonymizer/AnonymizationEngine';
import { TokenManager } from './anonymizer/TokenManager';
import { ConfigManager } from './utils/ConfigManager';
import { mainUIProvider } from './ui/mainUiProvider';
import { RuleEditorProvider } from './ui/RuleEditorProvider';
import { MappingsViewProvider } from './ui/MappingsViewProvider';
import { CommandExecutor } from './tools/CommandExecutor';
import { ScpTransferTool } from './tools/ScpTransferTool';
import { FileSystemTool } from './tools/FileSystemTool';
import { IacScanner } from './scanner/IacScanner';
import { SecretScanner } from './scanner/SecretScanner';
import { CloakdLogger } from './utils/CloakdLogger';
import { validateRules } from './anonymizer/RuleValidator';
import * as fs from 'fs';
import { AnonymizationRule } from './anonymizer/PatternLibrary';

let commandExecutorInstance: CommandExecutor | undefined;
let hasWarnedAboutAllToolScope = false;

interface RulesheetSelection {
    workspaceFolder: vscode.WorkspaceFolder;
    fileUri: vscode.Uri;
}

function sanitizeRulesheetName(input: string | undefined): string {
    const raw = (input ?? '').replace(/[/\\:*?"<>|]/g, '_').trim();
    return raw || 'defaultSheet';
}

function updateDevFiles(workspacePath: string, rulesheetRelativePath: string): void {
    const ignoreFiles = [
        path.join(workspacePath, '.gitignore'),
        path.join(workspacePath, '.copilotignore')
    ];

    for (const ignoreFile of ignoreFiles) {
        if (!fs.existsSync(ignoreFile)) {
            continue;
        }

        const content = fs.readFileSync(ignoreFile, 'utf8');
        if (!content.includes(rulesheetRelativePath)) {
            fs.appendFileSync(ignoreFile, `${rulesheetRelativePath}\n`);
        }
    }
}

async function pickWorkspaceFolder(
    placeHolder: string,
    preferredFolder?: vscode.WorkspaceFolder
): Promise<vscode.WorkspaceFolder | undefined> {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders || workspaceFolders.length === 0) {
        return undefined;
    }

    if (workspaceFolders.length === 1) {
        return workspaceFolders[0];
    }

    const items = workspaceFolders.map(folder => ({
        label: folder.name,
        description: folder.uri.fsPath,
        folder,
    }));

    const picked = await vscode.window.showQuickPick(items, {
        placeHolder,
    });

    if (picked) {
        return picked.folder;
    }

    return undefined;
}

async function findRulesheetsInWorkspace(folder: vscode.WorkspaceFolder): Promise<vscode.Uri[]> {
    return vscode.workspace.findFiles(
        new vscode.RelativePattern(folder, '**/*.cloakd.json')
    );
}

async function createRulesheetInWorkspace(folder: vscode.WorkspaceFolder): Promise<vscode.Uri> {
    const givenName = sanitizeRulesheetName(await vscode.window.showInputBox({
        placeHolder: 'Enter your rule file name (Else press enter for default name).'
    }));

    const cloakdFolder = path.join(folder.uri.fsPath, '.cloakd');
    if (!fs.existsSync(cloakdFolder)) {
        fs.mkdirSync(cloakdFolder, { recursive: true });
    }

    const newFilePath = path.join(cloakdFolder, `${givenName}.cloakd.json`);
    const selectedFile = vscode.Uri.file(newFilePath);

    const defaultData = {
        version: '0',
        enabled: false,
        rules: [],
        tokenConsistency: false,
        autoAnonymize: false,
        showPreview: true
    };

    const content = Buffer.from(JSON.stringify(defaultData, null, 4), 'utf8');
    await vscode.workspace.fs.writeFile(selectedFile, content);

    const relPath = path.relative(folder.uri.fsPath, selectedFile.fsPath).replace(/\\/g, '/');
    updateDevFiles(folder.uri.fsPath, relPath);

    vscode.window.showInformationMessage(`Created rule file: ${path.basename(selectedFile.fsPath)}.`);
    return selectedFile;
}

async function pickRulesheetInWorkspace(
    folder: vscode.WorkspaceFolder,
    allowCreate: boolean,
    placeHolder: string
): Promise<vscode.Uri | undefined> {
    const rulesheets = await findRulesheetsInWorkspace(folder);

    if (rulesheets.length === 0) {
        if (!allowCreate) {
            return undefined;
        }
        return createRulesheetInWorkspace(folder);
    }

    if (rulesheets.length === 1 && !allowCreate) {
        return rulesheets[0];
    }

    const items: Array<{
        label: string;
        description: string;
        fileUri?: vscode.Uri;
        createNew?: boolean;
    }> = rulesheets.map(file => ({
        label: path.basename(file.fsPath),
        description: vscode.workspace.asRelativePath(file, false),
        fileUri: file,
    }));

    if (allowCreate) {
        items.unshift({
            label: '$(add) Create new rulesheet',
            description: `Create under ${folder.name}/.cloakd`,
            createNew: true,
        });
    }

    const picked = await vscode.window.showQuickPick(items, { placeHolder });
    if (!picked) {
        return undefined;
    }

    if (picked.createNew) {
        return createRulesheetInWorkspace(folder);
    }

    return picked.fileUri;
}

async function selectWorkspaceAndRulesheet(
    allowCreate: boolean,
    preferredFolder?: vscode.WorkspaceFolder
): Promise<RulesheetSelection | undefined> {
    const folder = await pickWorkspaceFolder(
        'Pick the workspace folder for the active Cloakd session.',
        preferredFolder
    );
    if (!folder) {
        return undefined;
    }

    const fileUri = await pickRulesheetInWorkspace(
        folder,
        allowCreate,
        `Pick the rulesheet to use in workspace '${folder.name}'.`
    );

    if (!fileUri) {
        return undefined;
    }

    return { workspaceFolder: folder, fileUri };
}

function getConfigForFolder(folder: vscode.WorkspaceFolder): vscode.WorkspaceConfiguration {
    return vscode.workspace.getConfiguration('cloakd', folder.uri);
}

function getMaxToolRounds(folder: vscode.WorkspaceFolder): number {
    const configured = getConfigForFolder(folder).get<number>('agent.maxToolRounds', 10);
    const normalized = Number.isFinite(configured) ? Math.floor(configured) : 10;
    return Math.max(1, Math.min(100, normalized));
}

function shouldAutoClearOnSessionStart(folder: vscode.WorkspaceFolder): boolean {
    return getConfigForFolder(folder).get<boolean>('mappings.autoClearOnSessionStart', true);
}

function getToolDefinitions(folder: vscode.WorkspaceFolder): vscode.LanguageModelChatTool[] {
    const toolScope = getConfigForFolder(folder).get<string>('agent.toolScope', 'cloakdOnly');

    if (toolScope === 'all' && !hasWarnedAboutAllToolScope) {
        hasWarnedAboutAllToolScope = true;
        const warning =
            'Cloakd tool scope is set to all. Non-Cloakd tools may bypass Cloakd anonymization and are planned for deprecation.';
        CloakdLogger.warn(warning, { workspace: folder.name });
        void vscode.window.showWarningMessage(warning);
    }

    const visibleTools = toolScope === 'all'
        ? vscode.lm.tools
        : vscode.lm.tools.filter(t => t.name.startsWith('cloakd_'));

    return visibleTools.map(t => ({
        name: t.name,
        description: t.description,
        inputSchema: t.inputSchema ?? {}
    }));
}

async function processFileReferences(
    references: readonly vscode.ChatPromptReference[],
    anonymizationEngine: AnonymizationEngine
): Promise<string[]> {
    const contextParts: string[] = [];

    for (const ref of references) {
        if (!(ref.value instanceof vscode.Uri)) {
            continue;
        }

        try {
            const bytes = await vscode.workspace.fs.readFile(ref.value);
            const content = Buffer.from(bytes).toString('utf8');
            const anonResult = await anonymizationEngine.anonymize(content);
            const fileName = path.basename(ref.value.fsPath);
            contextParts.push(
                `[Attached file: ${fileName}]\n\`\`\`\n${anonResult.anonymized}\n\`\`\``
            );
        } catch (error) {
            CloakdLogger.warn('Skipping unreadable or non-anonymizable attachment.', {
                filePath: ref.value.fsPath,
                reason: error instanceof Error ? error.message : String(error)
            });
        }
    }

    return contextParts;
}

export async function activate(context: vscode.ExtensionContext): Promise<void> {
    console.log('The prompt hider is online.');
    const fallbackWorkspaceFolder = vscode.workspace.workspaceFolders?.[0];
    const idleConfigPath = path.join(
        fallbackWorkspaceFolder?.uri.fsPath ?? context.globalStorageUri.fsPath,
        '.cloakd',
        'idle.cloakd.json'
    );
 
    let activeWorkspaceFolder = fallbackWorkspaceFolder;
    let activeRulesheetUri: vscode.Uri | undefined;

    if (activeWorkspaceFolder) {
        CloakdLogger.setWorkspaceRoot(activeWorkspaceFolder.uri.fsPath);
        CloakdLogger.configure(activeWorkspaceFolder.uri);
    }
    CloakdLogger.info('Cloakd activating.', {
        workspace: activeWorkspaceFolder?.name ?? 'none',
        rulesheet: activeRulesheetUri ? path.basename(activeRulesheetUri.fsPath) : 'none',
        idle: !activeRulesheetUri,
    });

    const tokenManager = new TokenManager(context);
    const configManager = new ConfigManager(activeRulesheetUri?.fsPath ?? idleConfigPath);
    const anonymizationEngine = new AnonymizationEngine(tokenManager, configManager);

    const commandExecutor = new CommandExecutor(tokenManager);
    if (activeWorkspaceFolder) {
        commandExecutor.setConfigurationScope(activeWorkspaceFolder.uri);
    }
    commandExecutorInstance = commandExecutor;

    const scpTransferTool = new ScpTransferTool(commandExecutor);
    const fileSystemTool = new FileSystemTool(anonymizationEngine, tokenManager);
    if (activeWorkspaceFolder) {
        fileSystemTool.setWorkspaceScope(activeWorkspaceFolder.uri);
    }
    const mappingsViewProvider = new MappingsViewProvider(tokenManager);

    const statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 98);
    statusBarItem.command = 'cloakd.openUI';
    context.subscriptions.push(statusBarItem);
    let lastOperationalIssue: { level: 'error' | 'warn'; message: string } | undefined;

    const reportOperationalIssue = (
        level: 'error' | 'warn',
        message: string,
        details?: Record<string, unknown>
    ): void => {
        if (level === 'error') {
            CloakdLogger.error(message, details);
        } else {
            CloakdLogger.warn(message, details);
        }

        lastOperationalIssue = { level, message };
        void updateStatusBar();

        mainUIProvider.postMessage({
            command: 'errorNotice',
            level,
            message,
        });
    };

    const updateStatusBar = async (): Promise<void> => {
        const loadedConfig = activeRulesheetUri ? await configManager.loadFullConfig() : null;
        const ruleCount = loadedConfig?.rules?.length ?? 0;
        const rulesheetName = activeRulesheetUri
            ? path.basename(activeRulesheetUri.fsPath, '.cloakd.json')
            : 'No rulesheet selected';
        const workspaceName = activeWorkspaceFolder?.name ?? 'No workspace selected';
        const issuePrefix = lastOperationalIssue
            ? (lastOperationalIssue.level === 'error' ? '$(error) ' : '$(warning) ')
            : '';

        statusBarItem.text = `${issuePrefix}$(shield) Cloakd: ${workspaceName}/${rulesheetName} (${ruleCount})`;
        statusBarItem.tooltip =
            `Prompt Hider\n` +
            `Workspace: ${workspaceName}\n` +
            `Rulesheet: ${rulesheetName}\n` +
            `Rules: ${ruleCount}\n` +
            (lastOperationalIssue ? `Last issue: ${lastOperationalIssue.message}\n` : '') +
            `\n` +
            `Anonymization is applied only when using the @Cloakd chat participant.`;
        statusBarItem.show();
    };

    const ruleEditorProvider = new RuleEditorProvider(
        vscode.Uri.file(context.extensionPath),
        configManager,
        updateStatusBar
    );

    const applyRulesheetSelection = async (
        selection: RulesheetSelection,
        reason: 'startup' | 'switch'
    ): Promise<void> => {
        const previousRulesheetPath = activeRulesheetUri?.fsPath;
        activeWorkspaceFolder = selection.workspaceFolder;
        activeRulesheetUri = selection.fileUri;

        configManager.setConfigFilePath(activeRulesheetUri.fsPath);
        anonymizationEngine.invalidatePatternCache();
        commandExecutor.setConfigurationScope(activeWorkspaceFolder.uri);
        fileSystemTool.setWorkspaceScope(activeWorkspaceFolder.uri);
        CloakdLogger.setWorkspaceRoot(activeWorkspaceFolder.uri.fsPath);
        CloakdLogger.configure(activeWorkspaceFolder.uri);

        const isRulesheetChanged = previousRulesheetPath !== activeRulesheetUri.fsPath;
        if (reason === 'startup' && shouldAutoClearOnSessionStart(activeWorkspaceFolder)) {
            tokenManager.clearMappings();
            CloakdLogger.info('Token mappings auto-cleared on session start.', {
                workspace: activeWorkspaceFolder.name,
            });
        }

        if (reason === 'switch' && isRulesheetChanged) {
            tokenManager.clearMappings();
            CloakdLogger.info('Token mappings cleared on rulesheet switch (enforced privacy policy).', {
                workspace: activeWorkspaceFolder.name,
                rulesheet: path.basename(activeRulesheetUri.fsPath),
            });
        }

        lastOperationalIssue = undefined;

        mappingsViewProvider.refresh();
        await updateStatusBar();
        ruleEditorProvider.setConfigManager(configManager);
        mainUIProvider.refreshCurrentPanel();
    };

    const ensureActiveRulesheet = async (
        interaction: 'chat' | 'openUI' | 'scanIac' | 'scanSecrets' | 'scanCurrentFile' | 'anonymizeSelection' | 'switch'
    ): Promise<boolean> => {
        if (activeWorkspaceFolder && activeRulesheetUri) {
            return true;
        }

        const selection = await selectWorkspaceAndRulesheet(true, activeWorkspaceFolder);
        if (!selection) {
            const message = 'Cloakd is idle until you select or create a rulesheet.';
            reportOperationalIssue('warn', message, { interaction });
            vscode.window.showInformationMessage(message);
            return false;
        }

        await applyRulesheetSelection(selection, activeRulesheetUri ? 'switch' : 'startup');
        return true;
    };

    await updateStatusBar();
    CloakdLogger.info('Cloakd started in lazy mode. Rulesheet selection is deferred until first use.');

    const publishScannedRules = (fileName: string, scannedRules: Array<{
        id: string;
        pattern: string;
        replacement: string;
        confidence?: number;
        confidenceLevel?: 'high' | 'medium' | 'low';
        source: string;
    }>): void => {
        mainUIProvider.show(context, configManager, updateStatusBar);
        mainUIProvider.postMessage({
            command: 'scannedRules',
            rules: scannedRules,
            fileName,
        });
    };

    const scanSecretsWithProgress = async (
        displayName: string,
        scanOperation: (
            scanner: SecretScanner,
            onProgress: (percent: number) => void,
            cancellationToken: vscode.CancellationToken,
        ) => Promise<Array<{
            id: string;
            pattern: string;
            replacement: string;
            confidence?: number;
            confidenceLevel?: 'high' | 'medium' | 'low';
            source: string;
        }>>,
    ): Promise<void> => {
        await vscode.window.withProgress(
            {
                location: vscode.ProgressLocation.Notification,
                title: `Scanning ${displayName} for secrets...`,
                cancellable: true,
            },
            async (progress, cancellationToken) => {
                try {
                    const scanner = new SecretScanner();
                    let lastReported = 0;
                    const scannedRules = await scanOperation(scanner, (percent) => {
                        const safePercent = Math.max(lastReported, Math.min(100, Math.round(percent)));
                        progress.report({
                            increment: safePercent - lastReported,
                            message: `${safePercent}%`,
                        });
                        lastReported = safePercent;
                    }, cancellationToken);

                    if (cancellationToken.isCancellationRequested) {
                        return;
                    }

                    if (scannedRules.length === 0) {
                        vscode.window.showInformationMessage(`No likely secrets detected in ${displayName}.`);
                        return;
                    }

                    publishScannedRules(displayName, scannedRules.map(rule => ({
                        id: rule.id,
                        pattern: rule.pattern,
                        replacement: rule.replacement,
                        confidence: rule.confidence,
                        confidenceLevel: rule.confidenceLevel,
                        source: rule.source,
                    })));

                    vscode.window.showInformationMessage(
                        `Found ${scannedRules.length} likely secret${scannedRules.length === 1 ? '' : 's'} in ${displayName}. Review and save in the UI.`
                    );
                } catch (err) {
                    vscode.window.showErrorMessage(
                        `Failed to scan ${displayName}: ${err instanceof Error ? err.message : 'Unknown error'}`
                    );
                }
            }
        );
    };

    const scanCurrentFileCommand = vscode.commands.registerCommand('cloakd.scanCurrentFile', async () => {
        const hasRulesheet = await ensureActiveRulesheet('scanCurrentFile');
        if (!hasRulesheet) {
            return;
        }

        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showWarningMessage('Open a file in the editor before running a current-file secret scan.');
            return;
        }

        const document = editor.document;
        const displayName = path.basename(document.fileName || `untitled.${document.languageId || 'txt'}`);

        await scanSecretsWithProgress(displayName, (scanner, onProgress, cancellationToken) => {
            return scanner.scanText(document.getText(), document.fileName || displayName, {
                onProgress,
                cancelled: cancellationToken,
            });
        });
    });

    const legacyScanCurrentFileCommand = vscode.commands.registerCommand('prompt-hider.scanCurrentFile', async () => {
        await vscode.commands.executeCommand('cloakd.scanCurrentFile');
    });


    const toolDisposable = vscode.lm.registerTool('cloakd_execute_command', commandExecutor);
    const scpToolDisposable = vscode.lm.registerTool('cloakd_scp_transfer', scpTransferTool);
    const fileSystemToolDisposable = vscode.lm.registerTool('cloakd_filesystem', fileSystemTool);
    context.subscriptions.push(toolDisposable, scpToolDisposable, fileSystemToolDisposable);

    const chatParticipant = vscode.chat.createChatParticipant('cloakd', async (request, chatContext, stream, token) => {
        const hasRulesheet = await ensureActiveRulesheet('chat');
        if (!hasRulesheet || !activeWorkspaceFolder) {
            stream.markdown('**Cloakd** is idle. Select or create a rulesheet to continue.');
            return;
        }

        const userPrompt = request.prompt;
        let result;
        try {
            result = await anonymizationEngine.anonymize(userPrompt);
        } catch (error) {
            reportOperationalIssue(
                'error',
                'Prompt anonymization failed. Request was not sent to the model.',
                { reason: error instanceof Error ? error.message : String(error) }
            );
            stream.markdown('**Cloakd error**: Failed to anonymize your prompt safely. The request was stopped to avoid exposing raw sensitive values.');
            return;
        }

        if (result.stats.totalMatches > 0) {
            stream.markdown(`> **Cloakd**: ${result.stats.totalMatches} pattern(s) anonymized before sending.\n\n`);
            mappingsViewProvider.refresh();
        }

        const messages: vscode.LanguageModelChatMessage[] = [];

        for (const turn of chatContext.history) {
            if (turn instanceof vscode.ChatRequestTurn) {
                let histResult;
                try {
                    histResult = await anonymizationEngine.anonymize(turn.prompt);
                } catch (error) {
                    reportOperationalIssue(
                        'warn',
                        'Skipped a prior chat turn because anonymization failed.',
                        { reason: error instanceof Error ? error.message : String(error) }
                    );
                    continue;
                }
                const histFileParts = await processFileReferences(turn.references, anonymizationEngine);
                const histParts = histFileParts.length > 0
                    ? `${histResult.anonymized}\n\n${histFileParts.join('\n\n')}`
                    : histResult.anonymized;
                messages.push(vscode.LanguageModelChatMessage.User(histParts));
            } else if (turn instanceof vscode.ChatResponseTurn) {
                const responseText = turn.response
                    .filter((part): part is vscode.ChatResponseMarkdownPart =>
                        part instanceof vscode.ChatResponseMarkdownPart)
                    .map(part => part.value.value)
                    .join('');

                if (responseText) {
                    messages.push(vscode.LanguageModelChatMessage.Assistant(responseText));
                }
            }
        }

        const fileParts = await processFileReferences(request.references, anonymizationEngine);
        if (fileParts.length > 0) {
            stream.markdown(`> **Cloakd**: ${fileParts.length} file(s) attached and anonymized.\n\n`);
        }

        const currentUserMessage = fileParts.length > 0
            ? `${result.anonymized}\n\n${fileParts.join('\n\n')}`
            : result.anonymized;
        messages.push(vscode.LanguageModelChatMessage.User(currentUserMessage));

        const activeTokens = tokenManager.getAllMappings();
        if (activeTokens.size > 0) {
            const tokenList = [...new Set(activeTokens.values())].join(', ');
            messages.unshift(
                vscode.LanguageModelChatMessage.User(
                    `[SYSTEM — Cloakd context]\n` +
                    `The following anonymized tokens are currently active: ${tokenList}.\n` +
                    `When referring to these values or using tools, use these EXACT token names as they appear above. ` +
                    `Do NOT rename, reformat, or standardize them.\n` +
                    `Treat them as opaque identifiers.`
                )
            );
        }

        const toolDefs = getToolDefinitions(activeWorkspaceFolder);
        const maxToolRounds = getMaxToolRounds(activeWorkspaceFolder);

        try {
            let continueLoop = true;
            let iterations = 0;

            while (continueLoop) {
                continueLoop = false;
                iterations++;

                if (iterations > maxToolRounds) {
                    stream.markdown('\n\n> **Cloakd**: Reached maximum tool-call rounds. Stopping.\n');
                    break;
                }

                const modelResponse = await request.model.sendRequest(
                    messages,
                    { tools: toolDefs },
                    token
                );

                const assistantParts: (vscode.LanguageModelTextPart | vscode.LanguageModelToolCallPart)[] = [];

                for await (const part of modelResponse.stream) {
                    if (part instanceof vscode.LanguageModelTextPart) {
                        stream.markdown(part.value);
                        assistantParts.push(part);
                    } else if (part instanceof vscode.LanguageModelToolCallPart) {
                        assistantParts.push(part);
                        continueLoop = true;
                    }
                }

                if (continueLoop && assistantParts.length > 0) {
                    messages.push(vscode.LanguageModelChatMessage.Assistant(assistantParts));
                    const toolResultParts: vscode.LanguageModelToolResultPart[] = [];

                    for (const part of assistantParts) {
                        if (!(part instanceof vscode.LanguageModelToolCallPart)) {
                            continue;
                        }

                        try {
                            const toolResult = await vscode.lm.invokeTool(
                                part.name,
                                {
                                    input: part.input,
                                    toolInvocationToken: request.toolInvocationToken
                                },
                                token
                            );

                            toolResultParts.push(
                                new vscode.LanguageModelToolResultPart(part.callId, toolResult.content)
                            );
                        } catch (error) {
                            const message = error instanceof Error ? error.message : String(error);
                            reportOperationalIssue('error', `Tool execution failed for ${part.name}.`, {
                                toolName: part.name,
                                reason: message,
                            });
                            toolResultParts.push(
                                new vscode.LanguageModelToolResultPart(part.callId, [
                                    new vscode.LanguageModelTextPart(
                                        `Tool execution failed: ${message}`
                                    )
                                ])
                            );
                        }
                    }

                    messages.push(vscode.LanguageModelChatMessage.User(toolResultParts));
                }
            }
        } catch (err) {
            if (err instanceof vscode.LanguageModelError) {
                console.error('[Cloakd] LM error:', err.message, err.code);
                stream.markdown(`**Cloakd error**: ${err.message}`);
            } else {
                throw err;
            }
        } finally {
            mappingsViewProvider.refresh();
        }
    });

    context.subscriptions.push(chatParticipant);

    vscode.window.registerTreeDataProvider('cloakd.mappingsView', mappingsViewProvider);
    mappingsViewProvider.refresh();
    vscode.window.registerWebviewViewProvider(RuleEditorProvider.viewType, ruleEditorProvider);

    const openWebUI = vscode.commands.registerCommand('cloakd.openUI', () => {
        if (!activeRulesheetUri) {
            void ensureActiveRulesheet('openUI').then(hasRulesheet => {
                if (!hasRulesheet) {
                    return;
                }
                mainUIProvider.show(context, configManager, updateStatusBar);
            });
            return;
        }
        mainUIProvider.show(context, configManager, updateStatusBar);
    });

    const showMappingsCommand = vscode.commands.registerCommand('cloakd.showMappings', () => {
        mappingsViewProvider.refresh();
    });

    const clearMappingsCommand = vscode.commands.registerCommand('cloakd.clearMappings', async () => {
        const answer = await vscode.window.showWarningMessage(
            'Are you sure you want to clear all token mappings?',
            'Yes',
            'No'
        );
        if (answer === 'Yes') {
            tokenManager.clearMappings();
            mappingsViewProvider.refresh();
            vscode.window.showInformationMessage('Token mappings cleared');
        }
    });

    const switchRulesheetCommand = vscode.commands.registerCommand('cloakd.switchRulesheet', async () => {
        const selection = await selectWorkspaceAndRulesheet(true, activeWorkspaceFolder);
        if (!selection) {
            return;
        }

        await applyRulesheetSelection(selection, 'switch');
        vscode.window.showInformationMessage(
            `Active rulesheet switched to ${path.basename(selection.fileUri.fsPath)} in workspace ${selection.workspaceFolder.name}.`
        );
    });

    const activateCommand = vscode.commands.registerCommand('cloakd.activate', async () => {
        await vscode.commands.executeCommand('cloakd.switchRulesheet');
    });

    const anonymizeSelectionCommand = vscode.commands.registerCommand('cloakd.anonymize', async () => {
        const hasRulesheet = await ensureActiveRulesheet('anonymizeSelection');
        if (!hasRulesheet) {
            return;
        }

        const editor = vscode.window.activeTextEditor;
        if (!editor || editor.selection.isEmpty) {
            vscode.window.showInformationMessage('Select text first to anonymize.');
            return;
        }

        const selectedText = editor.document.getText(editor.selection);
        const anonResult = await anonymizationEngine.anonymize(selectedText);

        await editor.edit(editBuilder => {
            editBuilder.replace(editor.selection, anonResult.anonymized);
        });

        mappingsViewProvider.refresh();
    });

    const openRuleEditorCommand = vscode.commands.registerCommand('cloakd.openRuleEditor', async () => {
        await vscode.commands.executeCommand('workbench.view.extension.cloakd-sidebar');
        await vscode.commands.executeCommand('cloakd.openUI');
    });

    const scanIacFileCommand = vscode.commands.registerCommand('cloakd.scanIacFile', async () => {
        const hasRulesheet = await ensureActiveRulesheet('scanIac');
        if (!hasRulesheet) {
            return;
        }

        const fileUris = await vscode.window.showOpenDialog({
            canSelectMany: false,
            canSelectFolders: false,
            canSelectFiles: true,
            openLabel: 'Scan for Sensitive Patterns',
            filters: {
                'Infrastructure as Code': ['tf', 'tfvars', 'yml', 'yaml', 'json'],
                'All Files': ['*'],
            },
        });

        if (!fileUris || fileUris.length === 0) {
            return;
        }

        const filePath = fileUris[0].fsPath;

        try {
            const scannedRules = await IacScanner.scanFile(filePath);

            if (scannedRules.length === 0) {
                vscode.window.showInformationMessage('No sensitive patterns detected in the selected file.');
                return;
            }

            mainUIProvider.show(context, configManager, updateStatusBar);
            mainUIProvider.postMessage({
                command: 'scannedRules',
                rules: scannedRules.map(r => ({
                    id: r.id,
                    pattern: r.pattern,
                    replacement: r.replacement,
                })),
                fileName: path.basename(filePath),
            });

            vscode.window.showInformationMessage(
                `Found ${scannedRules.length} potential pattern(s) in ${path.basename(filePath)}. Review and save in the UI.`
            );
        } catch (err) {
            vscode.window.showErrorMessage(
                `Failed to scan file: ${err instanceof Error ? err.message : 'Unknown error'}`
            );
        }
    });

    const scanSecretsCommand = vscode.commands.registerCommand('cloakd.scanSecrets', async () => {
        const hasRulesheet = await ensureActiveRulesheet('scanSecrets');
        if (!hasRulesheet) {
            return;
        }

        const fileUris = await vscode.window.showOpenDialog({
            canSelectMany: false,
            canSelectFolders: false,
            canSelectFiles: true,
            openLabel: 'Scan for Secrets',
            filters: {
                'All Supported': ['tf', 'tfvars', 'py', 'js', 'ts', 'jsx', 'tsx', 'go', 'rb', 'java', 'cs', 'yml', 'yaml', 'json', 'env', 'sh', 'toml', 'ini', 'cfg', 'conf', 'properties', 'xml'],
                'All Files': ['*'],
            },
        });

        if (!fileUris || fileUris.length === 0) {
            return;
        }

        const filePath = fileUris[0].fsPath;
        await scanSecretsWithProgress(path.basename(filePath), (scanner, onProgress, cancellationToken) => {
            return scanner.scanFile(filePath, {
                onProgress,
                cancelled: cancellationToken,
            });
        });
    });

    context.subscriptions.push(
        scanCurrentFileCommand,
        legacyScanCurrentFileCommand,
        openWebUI,
        showMappingsCommand,
        clearMappingsCommand,
        switchRulesheetCommand,
        activateCommand,
        anonymizeSelectionCommand,
        openRuleEditorCommand,
        scanIacFileCommand,
        scanSecretsCommand
    );


    // quick-add rule command
    context.subscriptions.push(
        vscode.commands.registerCommand('cloakd.quickAddRule', async () => {
            const hasRulesheet = await ensureActiveRulesheet('openUI');
            if (!hasRulesheet) {
                return;
            }

            const editor = vscode.window.activeTextEditor;
            const selection = editor?.selection;
            const selectedText = selection && !selection.isEmpty ? editor.document.getText(selection) : undefined;

            if (!selectedText) {
                return vscode.window.showInformationMessage('Select text first to create a rule from it.');
            }

            const patternToObfuscate = await vscode.window.showInputBox({
                    prompt: 'Is this the pattern you want to obfuscate? Edit if needed, or leave as is.',
                    value: selectedText, // Pre-fill with highlighted text
                    ignoreFocusOut: true,
                });

            if (patternToObfuscate === undefined) {
                vscode.window.showInformationMessage('Quick Add cancelled.');
                return;
            }

            const normalizedPattern = patternToObfuscate.trim();
            if (!normalizedPattern) {
                vscode.window.showWarningMessage('You must provide a pattern to obfuscate.');
                return;
            }

            const givenReplacement = await vscode.window.showInputBox({
                prompt: 'Enter replacement word/phrase.',
                value: '',
                placeHolder: '',
                ignoreFocusOut: true
            })

            if (givenReplacement === undefined) {
                vscode.window.showInformationMessage('Quick Add cancelled.');
                return;
            }

            const normalizedReplacement = givenReplacement.trim();
            if (!normalizedReplacement) {
                vscode.window.showWarningMessage('You must provide a replacement.');
                return;
            }


            // Actually add the rule to the path
            const configPath = await configManager.getConfigFilePath();
            if (!configPath) {
                vscode.window.showErrorMessage('Cloakd: No config found or created.');
                return;
            }

            // Get current configs and add the new rule
            const currentConfigs = await configManager.loadFullConfig();

            const newlyCreatedRule:AnonymizationRule = {
                id: `rule_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
                type: "custom",
                pattern: normalizedPattern,
                replacement: normalizedReplacement,
                enabled: true,
                description: `${normalizedPattern} → ${normalizedReplacement} (added via quick-add)`,
            }

            if (currentConfigs) {
                const currentRules = currentConfigs.rules ?? [];
                const allRules = [...currentRules, newlyCreatedRule];
                const validation = validateRules(allRules);

                if (!validation.valid) {
                    vscode.window.showErrorMessage(`Quick Add failed: ${validation.errors[0]}`);
                    return;
                }

                if (validation.warnings.length > 0) {
                    console.warn('Quick Add rule has warnings:', validation.warnings);
                }

                await configManager.saveProjectRules(allRules);
                if (mainUIProvider.isPanelOpen()) {
                    mainUIProvider.refreshCurrentPanel();
                    vscode.window.showInformationMessage(`Rule added and saved: ${normalizedPattern} → ${normalizedReplacement}. Main panel refreshed.`);
                } else {
                    vscode.window.showInformationMessage(`Rule added and saved: ${normalizedPattern} → ${normalizedReplacement}. Open the UI to view all rules.`);
                }
            };
        })
    );
}

export function deactivate(): void {
    commandExecutorInstance?.dispose();
    commandExecutorInstance = undefined;
    console.log('VS Prompt Hider deactivated');
}
