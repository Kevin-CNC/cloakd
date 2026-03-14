import * as vscode from 'vscode';

export const CLOAKD_WRAP_PREFIX = 'cloakd_wrap_';

export interface WrappedToolMapping {
    wrappedName: string;
    originalName: string;
}

export interface WrappedToolRegistryOptions {
    shouldWrapTool?: (toolName: string) => boolean;
}

export function isCloakdNativeTool(toolName: string): boolean {
    return toolName.startsWith('cloakd_');
}

function normalizeToolNameForAlias(toolName: string): string {
    const normalized = toolName
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9_]+/g, '_')
        .replace(/^_+|_+$/g, '');

    return normalized || 'tool';
}

export class WrappedToolRegistry {
    private readonly wrappedToOriginal = new Map<string, string>();
    private readonly originalToWrapped = new Map<string, string>();
    private readonly wrappedDefinitions: vscode.LanguageModelChatTool[] = [];

    constructor(
        tools: readonly vscode.LanguageModelChatTool[],
        options?: WrappedToolRegistryOptions
    ) {
        const shouldWrap = options?.shouldWrapTool ?? ((toolName: string) => !isCloakdNativeTool(toolName));

        const usedNames = new Set<string>();

        for (const tool of tools) {
            if (!shouldWrap(tool.name)) {
                continue;
            }

            const wrappedName = this.buildUniqueWrappedName(tool.name, usedNames);
            usedNames.add(wrappedName);

            this.wrappedToOriginal.set(wrappedName, tool.name);
            this.originalToWrapped.set(tool.name, wrappedName);
            this.wrappedDefinitions.push({
                name: wrappedName,
                description: `Cloakd-wrapped alias for ${tool.name}.`,
                inputSchema: tool.inputSchema ?? {}
            });
        }
    }

    getWrappedToolDefinitions(): vscode.LanguageModelChatTool[] {
        return [...this.wrappedDefinitions];
    }

    getMappings(): WrappedToolMapping[] {
        return [...this.wrappedToOriginal.entries()].map(([wrappedName, originalName]) => ({
            wrappedName,
            originalName,
        }));
    }

    resolveOriginalName(toolName: string): string | undefined {
        return this.wrappedToOriginal.get(toolName);
    }

    resolveWrappedName(originalName: string): string | undefined {
        return this.originalToWrapped.get(originalName);
    }

    isWrappedTool(toolName: string): boolean {
        return this.wrappedToOriginal.has(toolName);
    }

    private buildUniqueWrappedName(originalName: string, usedNames: Set<string>): string {
        const base = `${CLOAKD_WRAP_PREFIX}${normalizeToolNameForAlias(originalName)}`;
        if (!usedNames.has(base)) {
            return base;
        }

        let suffix = 2;
        while (usedNames.has(`${base}_${suffix}`)) {
            suffix += 1;
        }

        return `${base}_${suffix}`;
    }
}
