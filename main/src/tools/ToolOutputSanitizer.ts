import * as vscode from 'vscode';

export interface ToolOutputSanitizerOptions {
    maxOutputSize: number;
}

function truncateText(value: string, maxOutputSize: number): string {
    if (maxOutputSize <= 0 || value.length <= maxOutputSize) {
        return value;
    }

    return `${value.slice(0, maxOutputSize)}\n[truncated by Cloakd output policy]`;
}

function sanitizeUnknownValue(value: unknown, reAnonymize: (text: string) => string, maxOutputSize: number): unknown {
    if (typeof value === 'string') {
        return truncateText(reAnonymize(value), maxOutputSize);
    }

    if (Array.isArray(value)) {
        return value.map(entry => sanitizeUnknownValue(entry, reAnonymize, maxOutputSize));
    }

    if (value !== null && typeof value === 'object') {
        const next: Record<string, unknown> = {};
        for (const [key, nested] of Object.entries(value)) {
            next[key] = sanitizeUnknownValue(nested, reAnonymize, maxOutputSize);
        }
        return next;
    }

    return value;
}

export class ToolOutputSanitizer {
    sanitizeToolContent(
        content: ReadonlyArray<vscode.LanguageModelTextPart | vscode.LanguageModelPromptTsxPart | vscode.LanguageModelDataPart | unknown>,
        reAnonymize: (text: string) => string,
        options: ToolOutputSanitizerOptions
    ): Array<vscode.LanguageModelTextPart | vscode.LanguageModelPromptTsxPart | vscode.LanguageModelDataPart | unknown> {
        const maxOutputSize = Math.max(1, Math.floor(options.maxOutputSize));

        return content.map(part => {
            if (part instanceof vscode.LanguageModelTextPart) {
                const safe = truncateText(reAnonymize(part.value), maxOutputSize);
                return new vscode.LanguageModelTextPart(safe);
            }

            if (part instanceof vscode.LanguageModelDataPart || part instanceof vscode.LanguageModelPromptTsxPart) {
                return part;
            }

            return sanitizeUnknownValue(part, reAnonymize, maxOutputSize);
        });
    }
}
