import * as path from 'path';
import * as fs from 'fs';
import * as vscode from 'vscode';
import { AnonymizationEngine } from '../anonymizer/AnonymizationEngine';
import { TokenManager } from '../anonymizer/TokenManager';
import { CloakdLogger } from '../utils/CloakdLogger';

type FileSystemOperation = 'read' | 'write' | 'patch' | 'delete' | 'list';

export interface FileSystemInput {
    operation: FileSystemOperation;
    path: string;
    content?: string;
    old_text?: string;
    new_text?: string;
    replace_all?: boolean;
    recursive?: boolean;
}

export class FileSystemTool implements vscode.LanguageModelTool<FileSystemInput> {
    private workspaceScopeUri: vscode.Uri | undefined;

    constructor(
        private readonly anonymizationEngine: AnonymizationEngine,
        private readonly tokenManager: TokenManager
    ) {}

    setWorkspaceScope(scopeUri: vscode.Uri): void {
        this.workspaceScopeUri = scopeUri;
    }

    prepareInvocation(
        options: vscode.LanguageModelToolInvocationPrepareOptions<FileSystemInput>
    ): vscode.PreparedToolInvocation {
        const op = options.input.operation;
        const targetPath = options.input.path;
        const destructive = op === 'write' || op === 'patch' || op === 'delete';

        const invocationMessage = (() => {
            switch (op) {
                case 'read':
                    return `Reading file '${targetPath}'`;
                case 'write':
                    return `Writing file '${targetPath}'`;
                case 'patch':
                    return `Patching file '${targetPath}'`;
                case 'delete':
                    return `Deleting path '${targetPath}'`;
                case 'list':
                    return `Listing directory '${targetPath}'`;
                default:
                    return `Running filesystem operation on '${targetPath}'`;
            }
        })();

        if (!destructive) {
            return { invocationMessage };
        }

        return {
            invocationMessage,
            confirmationMessages: {
                title: 'Allow Cloakd to modify workspace files?',
                message: `Operation: ${op}\nTarget: ${targetPath}`,
            },
        };
    }

    async invoke(
        options: vscode.LanguageModelToolInvocationOptions<FileSystemInput>
    ): Promise<vscode.LanguageModelToolResult> {
        const input = options.input;

        try {
            const targetPath = this.resolveWorkspacePath(this.deAnonymize(input.path));
            const targetUri = vscode.Uri.file(targetPath);

            switch (input.operation) {
                case 'read':
                    return await this.readFile(targetUri);
                case 'write':
                    return await this.writeFile(targetUri, input.content);
                case 'patch':
                    return await this.patchFile(targetUri, input.old_text, input.new_text, input.replace_all ?? false);
                case 'delete':
                    return await this.deletePath(targetUri, input.recursive ?? false);
                case 'list':
                    return await this.listDirectory(targetUri);
                default:
                    return this.errorResult(`Unsupported operation: ${input.operation}`);
            }
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            CloakdLogger.warn('Filesystem tool invocation failed.', {
                operation: input.operation,
                targetPath: input.path,
                reason: message,
            });
            return this.errorResult(message);
        }
    }

    private async readFile(targetUri: vscode.Uri): Promise<vscode.LanguageModelToolResult> {
        const bytes = await vscode.workspace.fs.readFile(targetUri);
        const content = Buffer.from(bytes).toString('utf8');
        const anonymized = await this.anonymizationEngine.anonymize(content);

        CloakdLogger.info('Filesystem read completed.', {
            targetPath: targetUri.fsPath,
            bytes: bytes.byteLength,
        });

        return this.textResult(anonymized.anonymized);
    }

    private async writeFile(targetUri: vscode.Uri, content: string | undefined): Promise<vscode.LanguageModelToolResult> {
        if (typeof content !== 'string') {
            return this.errorResult('`content` is required for write operations.');
        }

        const realContent = this.deAnonymize(content);
        await vscode.workspace.fs.createDirectory(vscode.Uri.file(path.dirname(targetUri.fsPath)));
        const data = Buffer.from(realContent, 'utf8');

        const usedWorkspaceEdit = await this.tryWriteUsingWorkspaceEdit(targetUri, realContent);
        if (!usedWorkspaceEdit) {
            await vscode.workspace.fs.writeFile(targetUri, data);
        }

        CloakdLogger.info('Filesystem write completed.', {
            targetPath: targetUri.fsPath,
            bytes: data.byteLength,
            mode: usedWorkspaceEdit ? 'workspaceEdit' : 'filesystem',
        });

        return this.textResult(`File written: ${targetUri.fsPath} (${data.byteLength} bytes)`);
    }

    private async patchFile(
        targetUri: vscode.Uri,
        oldText: string | undefined,
        newText: string | undefined,
        replaceAll: boolean = false
    ): Promise<vscode.LanguageModelToolResult> {
        if (typeof oldText !== 'string' || oldText.length === 0) {
            return this.errorResult('`old_text` must be a non-empty string for patch operations.');
        }

        if (typeof newText !== 'string') {
            return this.errorResult('`new_text` is required for patch operations.');
        }

        const bytes = await vscode.workspace.fs.readFile(targetUri);
        const currentContent = Buffer.from(bytes).toString('utf8');
        const realOldText = this.deAnonymize(oldText);
        const realNewText = this.deAnonymize(newText);

        const occurrenceIndexes = this.findOccurrenceIndexes(currentContent, realOldText);
        const occurrenceCount = occurrenceIndexes.length;
        if (occurrenceCount === 0) {
            return this.errorResult('`old_text` was not found in the target file.');
        }

        if (!replaceAll && occurrenceCount > 1) {
            return this.errorResult(
                `Patch is ambiguous: found ${occurrenceCount} matches for old_text. Set replace_all=true to replace every occurrence.`
            );
        }

        const updatedContent = replaceAll
            ? currentContent.split(realOldText).join(realNewText)
            : this.replaceAt(currentContent, occurrenceIndexes[0], realOldText.length, realNewText);

        const usedWorkspaceEdit = await this.tryWriteUsingWorkspaceEdit(targetUri, updatedContent);
        if (!usedWorkspaceEdit) {
            await vscode.workspace.fs.writeFile(targetUri, Buffer.from(updatedContent, 'utf8'));
        }

        CloakdLogger.info('Filesystem patch completed.', {
            targetPath: targetUri.fsPath,
            occurrenceCount,
            replaceAll,
            mode: usedWorkspaceEdit ? 'workspaceEdit' : 'filesystem',
        });

        const appliedCount = replaceAll ? occurrenceCount : 1;
        return this.textResult(`Patched ${appliedCount} occurrence(s) in ${targetUri.fsPath}`);
    }

    private async deletePath(targetUri: vscode.Uri, recursive: boolean): Promise<vscode.LanguageModelToolResult> {
        await vscode.workspace.fs.delete(targetUri, { recursive, useTrash: false });

        CloakdLogger.info('Filesystem delete completed.', {
            targetPath: targetUri.fsPath,
            recursive,
        });

        return this.textResult(`Deleted: ${targetUri.fsPath}`);
    }

    private async listDirectory(targetUri: vscode.Uri): Promise<vscode.LanguageModelToolResult> {
        const entries = await vscode.workspace.fs.readDirectory(targetUri);
        const formatted = entries
            .map(([name, type]) => {
                if (type === vscode.FileType.Directory) {
                    return `${name}\t[dir]`;
                }
                if (type === vscode.FileType.File) {
                    return `${name}\t[file]`;
                }
                return `${name}\t[other]`;
            })
            .join('\n');

        CloakdLogger.info('Filesystem list completed.', {
            targetPath: targetUri.fsPath,
            count: entries.length,
        });

        return this.textResult(formatted || '(empty directory)');
    }

    private resolveWorkspacePath(rawPath: string): string {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders || workspaceFolders.length === 0) {
            throw new Error('No workspace folder is open.');
        }

        const normalizedInput = this.normalizeInputPath(rawPath);
        const preferredFolder = this.workspaceScopeUri
            ? workspaceFolders.find(folder => folder.uri.toString() === this.workspaceScopeUri!.toString())
            : undefined;

        const orderedFolders = preferredFolder
            ? [preferredFolder, ...workspaceFolders.filter(folder => folder.uri.toString() !== preferredFolder.uri.toString())]
            : [...workspaceFolders];

        const roots = orderedFolders.map(folder => path.resolve(folder.uri.fsPath));
        const absoluteTarget = this.resolveAgainstWorkspaceRoots(normalizedInput, roots);

        const allowed = roots.some(root => this.isPathWithin(root, absoluteTarget));
        if (!allowed) {
            throw new Error('Path is outside the workspace. Only workspace files can be accessed.');
        }

        return absoluteTarget;
    }

    private resolveAgainstWorkspaceRoots(inputPath: string, roots: string[]): string {
        const shouldTryEachRoot = !path.isAbsolute(inputPath)
            || (process.platform === 'win32' && this.isWindowsRootRelative(inputPath));

        if (!shouldTryEachRoot) {
            return path.resolve(inputPath);
        }

        const candidates = roots.map(root => this.toAbsolutePath(inputPath, root));
        const existingTarget = candidates.find(candidate => this.existsOnDisk(candidate));
        if (existingTarget) {
            return existingTarget;
        }

        const existingParent = candidates.find(candidate => this.existsOnDisk(path.dirname(candidate)));
        if (existingParent) {
            return existingParent;
        }

        return candidates[0];
    }

    private normalizeInputPath(inputPath: string): string {
        const trimmed = inputPath.trim();
        if (trimmed.length >= 2) {
            const first = trimmed[0];
            const last = trimmed[trimmed.length - 1];
            if ((first === '"' && last === '"') || (first === '\'' && last === '\'')) {
                return trimmed.slice(1, -1).trim();
            }
        }

        return trimmed;
    }

    private toAbsolutePath(inputPath: string, baseRoot: string): string {
        if (!path.isAbsolute(inputPath)) {
            return path.resolve(baseRoot, inputPath);
        }

        if (process.platform === 'win32' && this.isWindowsRootRelative(inputPath)) {
            const withoutLeadingSlashes = inputPath.replace(/^[/\\]+/, '');
            return path.resolve(baseRoot, withoutLeadingSlashes);
        }

        return path.resolve(inputPath);
    }

    private isWindowsRootRelative(inputPath: string): boolean {
        const hasDriveLetter = /^[a-zA-Z]:[\\/]/.test(inputPath);
        const isUnc = /^\\\\/.test(inputPath);
        const startsWithSlash = /^[\\/]/.test(inputPath);
        return startsWithSlash && !hasDriveLetter && !isUnc;
    }

    private isPathWithin(root: string, target: string): boolean {
        const normalizedRoot = path.resolve(root);
        const normalizedTarget = path.resolve(target);

        if (process.platform === 'win32') {
            const lowerRoot = normalizedRoot.toLowerCase();
            const lowerTarget = normalizedTarget.toLowerCase();
            return lowerTarget === lowerRoot || lowerTarget.startsWith(`${lowerRoot}${path.sep}`);
        }

        return normalizedTarget === normalizedRoot || normalizedTarget.startsWith(`${normalizedRoot}${path.sep}`);
    }

    private findOccurrenceIndexes(text: string, needle: string): number[] {
        const indexes: number[] = [];
        let index = 0;

        while (true) {
            index = text.indexOf(needle, index);
            if (index === -1) {
                break;
            }

            indexes.push(index);
            index += needle.length;
        }

        return indexes;
    }

    private replaceAt(text: string, start: number, length: number, replacement: string): string {
        return `${text.slice(0, start)}${replacement}${text.slice(start + length)}`;
    }

    private existsOnDisk(filePath: string): boolean {
        return fs.existsSync(filePath);
    }

    private async tryWriteUsingWorkspaceEdit(targetUri: vscode.Uri, content: string): Promise<boolean> {
        const openDoc = vscode.workspace.textDocuments.find(doc => doc.uri.toString() === targetUri.toString());
        if (!openDoc) {
            return false;
        }

        const edit = new vscode.WorkspaceEdit();
        const endPosition = openDoc.lineCount === 0
            ? new vscode.Position(0, 0)
            : openDoc.lineAt(openDoc.lineCount - 1).range.end;
        edit.replace(openDoc.uri, new vscode.Range(new vscode.Position(0, 0), endPosition), content);
        return vscode.workspace.applyEdit(edit);
    }

    private deAnonymize(text: string): string {
        const reverse = this.tokenManager.getReverseMappings();
        const sorted = [...reverse.keys()].sort((a, b) => b.length - a.length);

        let result = text;
        for (const token of sorted) {
            const original = reverse.get(token)!;
            result = result.replace(new RegExp(this.escapeRegex(token), 'g'), original);
        }
        return result;
    }

    private escapeRegex(value: string): string {
        return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }

    private textResult(message: string): vscode.LanguageModelToolResult {
        return new vscode.LanguageModelToolResult([
            new vscode.LanguageModelTextPart(message),
        ]);
    }

    private errorResult(message: string): vscode.LanguageModelToolResult {
        return this.textResult(`Filesystem error: ${message}`);
    }
}
