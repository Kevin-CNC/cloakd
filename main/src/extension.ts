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
import { PromptHiderLogger } from './utils/PromptHiderLogger';
import * as fs from 'fs';

let commandExecutorInstance: CommandExecutor | undefined;

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
        new vscode.RelativePattern(folder, '**/*.prompthider.json')
    );
}

async function createRulesheetInWorkspace(folder: vscode.WorkspaceFolder): Promise<vscode.Uri> {
    const givenName = sanitizeRulesheetName(await vscode.window.showInputBox({
        placeHolder: 'Enter your rule file name (Else press enter for default name).'
    }));

    const promptHiderFolder = path.join(folder.uri.fsPath, '.prompthider');
    if (!fs.existsSync(promptHiderFolder)) {
        fs.mkdirSync(promptHiderFolder, { recursive: true });
    }

    const newFilePath = path.join(promptHiderFolder, `${givenName}.prompthider.json`);
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
            description: `Create under ${folder.name}/.prompthider`,
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
        'Pick the workspace folder for the active PromptHider session.',
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
    return vscode.workspace.getConfiguration('prompthider', folder.uri);
}

function getMaxToolRounds(folder: vscode.WorkspaceFolder): number {
    const configured = getConfigForFolder(folder).get<number>('agent.maxToolRounds', 10);
    const normalized = Number.isFinite(configured) ? Math.floor(configured) : 10;
    return Math.max(1, Math.min(100, normalized));
}

function shouldAutoClearOnSessionStart(folder: vscode.WorkspaceFolder): boolean {
    return getConfigForFolder(folder).get<boolean>('mappings.autoClearOnSessionStart', true);
}

function shouldAutoClearOnRulesheetSwitch(folder: vscode.WorkspaceFolder): boolean {
    return getConfigForFolder(folder).get<boolean>('mappings.autoClearOnRulesheetSwitch', true);
}

function getToolDefinitions(folder: vscode.WorkspaceFolder): vscode.LanguageModelChatTool[] {
    const toolScope = getConfigForFolder(folder).get<string>('agent.toolScope', 'prompthiderOnly');
    const visibleTools = toolScope === 'all'
        ? vscode.lm.tools
        : vscode.lm.tools.filter(t => t.name.startsWith('prompthider_'));

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
            PromptHiderLogger.warn('Skipping unreadable or non-anonymizable attachment.', {
                filePath: ref.value.fsPath,
                reason: error instanceof Error ? error.message : String(error)
            });
        }
    }

    return contextParts;
}

export async function activate(context: vscode.ExtensionContext): Promise<void> {
    console.log('The prompt hider is online.');

    const initialSelection = await selectWorkspaceAndRulesheet(true);
    const fallbackWorkspaceFolder = vscode.workspace.workspaceFolders?.[0];
    const idleConfigPath = path.join(
        fallbackWorkspaceFolder?.uri.fsPath ?? context.globalStorageUri.fsPath,
        '.prompthider',
        'idle.prompthider.json'
    );
 
    let activeWorkspaceFolder = initialSelection?.workspaceFolder ?? fallbackWorkspaceFolder;
    let activeRulesheetUri = initialSelection?.fileUri;

    if (activeWorkspaceFolder) {
        PromptHiderLogger.setWorkspaceRoot(activeWorkspaceFolder.uri.fsPath);
        PromptHiderLogger.configure(activeWorkspaceFolder.uri);
    }
    PromptHiderLogger.info('PromptHider activating.', {
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
    statusBarItem.command = 'prompthider.openUI';
    context.subscriptions.push(statusBarItem);
    let lastOperationalIssue: { level: 'error' | 'warn'; message: string } | undefined;

    const reportOperationalIssue = (
        level: 'error' | 'warn',
        message: string,
        details?: Record<string, unknown>
    ): void => {
        if (level === 'error') {
            PromptHiderLogger.error(message, details);
        } else {
            PromptHiderLogger.warn(message, details);
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
            ? path.basename(activeRulesheetUri.fsPath, '.prompthider.json')
            : 'No rulesheet selected';
        const workspaceName = activeWorkspaceFolder?.name ?? 'No workspace selected';
        const issuePrefix = lastOperationalIssue
            ? (lastOperationalIssue.level === 'error' ? '$(error) ' : '$(warning) ')
            : '';

        statusBarItem.text = `${issuePrefix}$(shield) PromptHider: ${workspaceName}/${rulesheetName} (${ruleCount})`;
        statusBarItem.tooltip =
            `Prompt Hider\n` +
            `Workspace: ${workspaceName}\n` +
            `Rulesheet: ${rulesheetName}\n` +
            `Rules: ${ruleCount}\n` +
            (lastOperationalIssue ? `Last issue: ${lastOperationalIssue.message}\n` : '') +
            `\n` +
            `Anonymization is applied only when using the @PromptHider chat participant.`;
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
        commandExecutor.setConfigurationScope(activeWorkspaceFolder.uri);
        fileSystemTool.setWorkspaceScope(activeWorkspaceFolder.uri);
        PromptHiderLogger.setWorkspaceRoot(activeWorkspaceFolder.uri.fsPath);
        PromptHiderLogger.configure(activeWorkspaceFolder.uri);

        const isRulesheetChanged = previousRulesheetPath !== activeRulesheetUri.fsPath;
        if (reason === 'startup' && shouldAutoClearOnSessionStart(activeWorkspaceFolder)) {
            tokenManager.clearMappings();
            PromptHiderLogger.info('Token mappings auto-cleared on session start.', {
                workspace: activeWorkspaceFolder.name,
            });
        }
        if (reason === 'switch' && isRulesheetChanged && shouldAutoClearOnRulesheetSwitch(activeWorkspaceFolder)) {
            tokenManager.clearMappings();
            PromptHiderLogger.info('Token mappings auto-cleared on rulesheet switch.', {
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
        interaction: 'chat' | 'openUI' | 'scanIac' | 'anonymizeSelection' | 'switch'
    ): Promise<boolean> => {
        if (activeWorkspaceFolder && activeRulesheetUri) {
            return true;
        }

        const selection = await selectWorkspaceAndRulesheet(true, activeWorkspaceFolder);
        if (!selection) {
            const message = 'PromptHider is idle until you select or create a rulesheet.';
            reportOperationalIssue('warn', message, { interaction });
            vscode.window.showInformationMessage(message);
            return false;
        }

        await applyRulesheetSelection(selection, activeRulesheetUri ? 'switch' : 'startup');
        return true;
    };

    if (initialSelection) {
        await applyRulesheetSelection(initialSelection, 'startup');
    } else {
        await updateStatusBar();
        PromptHiderLogger.warn('PromptHider started in idle mode (no rulesheet selected).');
    }

    const toolDisposable = vscode.lm.registerTool('prompthider_execute_command', commandExecutor);
    const scpToolDisposable = vscode.lm.registerTool('prompthider_scp_transfer', scpTransferTool);
    const fileSystemToolDisposable = vscode.lm.registerTool('prompthider_filesystem', fileSystemTool);
    context.subscriptions.push(toolDisposable, scpToolDisposable, fileSystemToolDisposable);

    const chatParticipant = vscode.chat.createChatParticipant('prompthider', async (request, chatContext, stream, token) => {
        const hasRulesheet = await ensureActiveRulesheet('chat');
        if (!hasRulesheet || !activeWorkspaceFolder) {
            stream.markdown('**PromptHider** is idle. Select or create a rulesheet to continue.');
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
            stream.markdown('**PromptHider error**: Failed to anonymize your prompt safely. The request was stopped to avoid exposing raw sensitive values.');
            return;
        }

        if (result.stats.totalMatches > 0) {
            stream.markdown(`> **PromptHider**: ${result.stats.totalMatches} pattern(s) anonymized before sending.\n\n`);
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
            stream.markdown(`> **PromptHider**: ${fileParts.length} file(s) attached and anonymized.\n\n`);
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
                    `[SYSTEM — PromptHider context]\n` +
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
                    stream.markdown('\n\n> **PromptHider**: Reached maximum tool-call rounds. Stopping.\n');
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
                console.error('[PromptHider] LM error:', err.message, err.code);
                stream.markdown(`**PromptHider error**: ${err.message}`);
            } else {
                throw err;
            }
        } finally {
            mappingsViewProvider.refresh();
        }
    });

    context.subscriptions.push(chatParticipant);

    vscode.window.registerTreeDataProvider('prompthider.mappingsView', mappingsViewProvider);
    mappingsViewProvider.refresh();
    vscode.window.registerWebviewViewProvider(RuleEditorProvider.viewType, ruleEditorProvider);

    const openWebUI = vscode.commands.registerCommand('prompthider.openUI', () => {
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

    const showMappingsCommand = vscode.commands.registerCommand('prompthider.showMappings', () => {
        mappingsViewProvider.refresh();
    });

    const clearMappingsCommand = vscode.commands.registerCommand('prompthider.clearMappings', async () => {
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

    const switchRulesheetCommand = vscode.commands.registerCommand('prompthider.switchRulesheet', async () => {
        const selection = await selectWorkspaceAndRulesheet(true, activeWorkspaceFolder);
        if (!selection) {
            return;
        }

        await applyRulesheetSelection(selection, 'switch');
        vscode.window.showInformationMessage(
            `Active rulesheet switched to ${path.basename(selection.fileUri.fsPath)} in workspace ${selection.workspaceFolder.name}.`
        );
    });

    const activateCommand = vscode.commands.registerCommand('prompthider.activate', async () => {
        await vscode.commands.executeCommand('prompthider.switchRulesheet');
    });

    const anonymizeSelectionCommand = vscode.commands.registerCommand('prompthider.anonymize', async () => {
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

    const openRuleEditorCommand = vscode.commands.registerCommand('prompthider.openRuleEditor', async () => {
        await vscode.commands.executeCommand('workbench.view.extension.prompthider-sidebar');
        await vscode.commands.executeCommand('prompthider.openUI');
    });

    const scanIacFileCommand = vscode.commands.registerCommand('prompthider.scanIacFile', async () => {
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

            setTimeout(() => {
                mainUIProvider.postMessage({
                    command: 'scannedRules',
                    rules: scannedRules.map(r => ({
                        id: r.id,
                        pattern: r.pattern,
                        replacement: r.replacement,
                    })),
                    fileName: path.basename(filePath),
                });
            }, 500);

            vscode.window.showInformationMessage(
                `Found ${scannedRules.length} potential pattern(s) in ${path.basename(filePath)}. Review and save in the UI.`
            );
        } catch (err) {
            vscode.window.showErrorMessage(
                `Failed to scan file: ${err instanceof Error ? err.message : 'Unknown error'}`
            );
        }
    });

    context.subscriptions.push(
        openWebUI,
        showMappingsCommand,
        clearMappingsCommand,
        switchRulesheetCommand,
        activateCommand,
        anonymizeSelectionCommand,
        openRuleEditorCommand,
        scanIacFileCommand
    );
}

export function deactivate(): void {
    commandExecutorInstance?.dispose();
    commandExecutorInstance = undefined;
    console.log('VS Prompt Hider deactivated');
}
