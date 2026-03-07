import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

type LogLevel = 'error' | 'warn' | 'info' | 'debug';

interface LogEntry {
    timestamp: string;
    level: LogLevel;
    message: string;
    context?: unknown;
}

export class CloakdLogger {
    private static output = vscode.window.createOutputChannel('Cloakd');
    private static workspaceRoot: string | undefined;
    private static minLevel: LogLevel = 'warn';
    private static readonly logFileName = 'cloakd.log.jsonl';

    static configure(scopeUri?: vscode.Uri): void {
        const cfg = vscode.workspace.getConfiguration('cloakd', scopeUri);
        const configured = cfg.get<string>('logging.level', 'warn');
        if (configured === 'error' || configured === 'warn' || configured === 'info' || configured === 'debug') {
            this.minLevel = configured;
        } else {
            this.minLevel = 'warn';
        }
    }

    static setWorkspaceRoot(rootPath: string | undefined): void {
        this.workspaceRoot = rootPath;
    }

    static show(): void {
        this.output.show(true);
    }

    static error(message: string, context?: unknown): void {
        this.log('error', message, context);
    }

    static warn(message: string, context?: unknown): void {
        this.log('warn', message, context);
    }

    static info(message: string, context?: unknown): void {
        this.log('info', message, context);
    }

    static debug(message: string, context?: unknown): void {
        this.log('debug', message, context);
    }

    private static log(level: LogLevel, message: string, context?: unknown): void {
        if (!this.shouldLog(level)) {
            return;
        }

        const entry: LogEntry = {
            timestamp: new Date().toISOString(),
            level,
            message,
            context,
        };

        const line = `[${entry.timestamp}] [${level.toUpperCase()}] ${message}`;
        this.output.appendLine(line);
        if (context !== undefined) {
            this.output.appendLine(`  context: ${this.safeStringify(context)}`);
        }

        this.appendLocalLog(entry);
    }

    private static shouldLog(level: LogLevel): boolean {
        const order: Record<LogLevel, number> = {
            error: 0,
            warn: 1,
            info: 2,
            debug: 3,
        };

        return order[level] <= order[this.minLevel];
    }

    private static appendLocalLog(entry: LogEntry): void {
        if (!this.workspaceRoot) {
            return;
        }

        try {
            const logDir = path.join(this.workspaceRoot, '.cloakd');
            if (!fs.existsSync(logDir)) {
                fs.mkdirSync(logDir, { recursive: true });
            }

            const logPath = path.join(logDir, this.logFileName);
            fs.appendFileSync(logPath, `${this.safeStringify(entry)}\n`, 'utf8');
        } catch {
            // Best-effort logging only.
        }
    }

    private static safeStringify(value: unknown): string {
        try {
            return JSON.stringify(value);
        } catch {
            return '[unserializable]';
        }
    }
}
