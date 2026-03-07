import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as os from 'os';
import * as path from 'path';
import { TokenManager } from '../anonymizer/TokenManager';
import { CloakdLogger } from '../utils/CloakdLogger';

export interface CommandInput {
    command: string;
}

type ExecutionMode = 'captured' | 'terminal';

interface ExecutionResult {
    stdout: string;
    stderr: string;
    exitCode: number;
}

class InteractiveCommandError extends Error {
    constructor(readonly reason: string) {
        super(
            `Interactive input is required (${reason}). Switch 'cloakd.agent.executionMode' to 'terminal' or run the command directly in the Cloakd terminal.`
        );
        this.name = 'InteractiveCommandError';
    }
}

/** Command classification for adaptive timeout and flag injection. */
type CommandType = 'ssh' | 'scp' | 'sftp' | 'local';

export class CommandExecutor implements vscode.LanguageModelTool<CommandInput> {
    private terminal: vscode.Terminal | undefined;
    private configurationScopeUri: vscode.Uri | undefined;

    // ── Adaptive timeouts ────────────────────────────────
    private static readonly LOCAL_TIMEOUT_MS  = 30_000;   // 30 s — local commands
    private static readonly REMOTE_TIMEOUT_MS = 120_000;  // 120 s — SSH / SCP / SFTP
    private static readonly MAX_BUFFER        = 1024 * 1024; // 1 MB

    // ── SSH session persistence (Unix only) ──────────────
    // ControlMaster reuses a single TCP connection for all SSH invocations to the
    // same host:port:user tuple. ControlPersist keeps the master alive N seconds
    // after the last client disconnects, avoiding repeated key exchanges.
    // Windows OpenSSH does not support Unix-domain control sockets so this is
    // transparently skipped on win32.
    private static readonly SSH_CONTROL_PERSIST_SECS = 300;

    constructor(private readonly tokenManager: TokenManager) {}

    setConfigurationScope(scopeUri: vscode.Uri): void {
        this.configurationScopeUri = scopeUri;
    }

    prepareInvocation(
        options: vscode.LanguageModelToolInvocationPrepareOptions<CommandInput>
    ): vscode.PreparedToolInvocation {
        const command = options.input.command?.trim() ?? '';
        const preview = command.length > 120 ? `${command.slice(0, 117)}...` : command;

        return {
            invocationMessage: `Executing command: ${preview || '(empty command)'}`,
            confirmationMessages: {
                title: 'Allow Cloakd to execute this shell command?',
                message: preview || 'No command was provided.',
            },
        };
    }

    // ── Tool interface (LanguageModelTool) ────────────────

    async invoke(
        options: vscode.LanguageModelToolInvocationOptions<CommandInput>,
        cancellationToken: vscode.CancellationToken
    ): Promise<vscode.LanguageModelToolResult> {
        const rawCommand = options.input.command?.trim();

        if (!rawCommand) {
            return new vscode.LanguageModelToolResult([
                new vscode.LanguageModelTextPart('Error: no command was provided.')
            ]);
        }

        try {
            const executionMode = this.getExecutionMode();
            CloakdLogger.debug('Tool command invocation requested.', {
                executionMode,
                commandPreview: rawCommand,
            });
            const { exitCode, safeStdout, safeStderr, mode } = await this.executeCommand(
                rawCommand,
                cancellationToken,
                { executionMode }
            );

            if (mode === 'terminal') {
                return new vscode.LanguageModelToolResult([
                    new vscode.LanguageModelTextPart(
                        'Command sent to the Cloakd terminal for interactive/background execution. No captured output is available in terminal mode.'
                    )
                ]);
            }

            const summary = [
                `Exit code: ${exitCode}`,
                safeStdout ? `\nOutput:\n${safeStdout}` : '',
                safeStderr ? `\nErrors:\n${safeStderr}` : ''
            ].join('');

            return new vscode.LanguageModelToolResult([
                new vscode.LanguageModelTextPart(summary)
            ]);
        } catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            CloakdLogger.error('Command tool invocation failed.', {
                error: msg,
                commandPreview: rawCommand,
            });
            return new vscode.LanguageModelToolResult([
                new vscode.LanguageModelTextPart(`Execution error: ${msg}`)
            ]);
        }
    }

    // ── Public API (used by invoke() and by other tools) ──

    /**
     * Execute a shell command with full anonymization round-trip.
     *   1. De-anonymize the command (tokens → real values)
     *   2. Optionally mirror the real command to the Cloakd terminal
     *   3. Run via child_process.exec with adaptive timeout
     *   4. Re-anonymize stdout / stderr (real values → tokens)
     *
     * Other tools (e.g. ScpTransferTool) call this instead of re-implementing
     * the capture + anonymization pipeline.
     */
    public async executeCommand(
        rawCommand: string,
        cancellationToken: vscode.CancellationToken,
        options?: { executionMode?: ExecutionMode }
    ): Promise<{ exitCode: number; safeStdout: string; safeStderr: string; mode: ExecutionMode }> {
        const realCommand = this.deAnonymize(rawCommand);
        const interactiveReason = this.detectInteractiveReason(realCommand);

        const mode = options?.executionMode ?? this.getExecutionMode();

        if (mode === 'captured' && interactiveReason) {
            CloakdLogger.warn('Blocked interactive command in captured mode.', {
                reason: interactiveReason,
                commandPreview: rawCommand,
            });
            throw new InteractiveCommandError(interactiveReason);
        }

        if (mode === 'terminal') {
            this.ensureTerminal();
            this.terminal!.show(true);
            this.terminal!.sendText(realCommand, true);
            CloakdLogger.info('Command handed off to Cloakd terminal.', {
                commandPreview: rawCommand,
            });
            return {
                exitCode: 0,
                safeStdout: '',
                safeStderr: '',
                mode,
            };
        }

        const result = await this.capture(realCommand, cancellationToken);
        CloakdLogger.info('Captured command completed.', {
            exitCode: result.exitCode,
            commandPreview: rawCommand,
        });

        return {
            exitCode: result.exitCode,
            safeStdout: this.reAnonymize(result.stdout),
            safeStderr: this.reAnonymize(result.stderr),
            mode,
        };
    }

    private getExecutionMode(): ExecutionMode {
        const config = vscode.workspace.getConfiguration('cloakd', this.configurationScopeUri);
        const configured = config.get<string>('agent.executionMode', 'captured');
        return configured === 'terminal' ? 'terminal' : 'captured';
    }

    // ── Command classification ───────────────────────────

    /** Classify a command string to determine timeout and flag injection. */
    private classifyCommand(command: string): CommandType {
        const trimmed = command.trimStart();
        if (/^(?:\S+=\S+\s+)*ssh\s/i.test(trimmed))  { return 'ssh'; }
        if (/^(?:\S+=\S+\s+)*scp\s/i.test(trimmed))  { return 'scp'; }
        if (/^(?:\S+=\S+\s+)*sftp\s/i.test(trimmed)) { return 'sftp'; }
        return 'local';
    }

    /** Return the appropriate timeout for a command type. */
    private getTimeout(type: CommandType): number {
        return type === 'local'
            ? CommandExecutor.LOCAL_TIMEOUT_MS
            : CommandExecutor.REMOTE_TIMEOUT_MS;
    }

    // ── Command preparation ──────────────────────────────

    /**
     * Prepare a command for non-interactive, captured execution.
     *
     * - **SSH**: injects `-T` (no PTY) + `-o BatchMode=yes` (fail-fast on
     *   password / host-key prompts) + ControlMaster options on Unix for
     *   session reuse across tool calls.
     * - **SCP / SFTP**: injects `-o BatchMode=yes` + ControlMaster on Unix.
     *   Does NOT inject `-T` (not a valid flag for scp/sftp).
     * - **Local**: returned as-is.
     */
    private prepareForCapture(command: string, type: CommandType): string {
        if (type === 'local') { return command; }

        const trimmed = command.trimStart();
        const sshOpts: string[] = [];

        // -T disables pseudo-terminal allocation — valid for `ssh` only
        if (type === 'ssh') {
            sshOpts.push('-T');
        }

        // Fail-fast on password / host-key prompts instead of hanging
        sshOpts.push('-o', 'BatchMode=yes');

        // SSH ControlMaster for session reuse (Unix only — Windows OpenSSH
        // does not support Unix-domain control sockets).
        if (process.platform !== 'win32') {
            const controlPath = path.join(
                os.tmpdir(),
                'cloakd_ssh_%h_%p_%r'
            );
            sshOpts.push(
                '-o', 'ControlMaster=auto',
                '-o', `ControlPath=${controlPath}`,
                '-o', `ControlPersist=${CommandExecutor.SSH_CONTROL_PERSIST_SECS}`
            );
        }

        const optsStr = sshOpts.join(' ');

        // Inject options right after the command name (ssh / scp / sftp),
        // preserving any leading env-var assignments (VAR=val ssh ...).
        return trimmed.replace(
            new RegExp(`^((?:\\S+=\\S+\\s+)*${type})\\s`, 'i'),
            `$1 ${optsStr} `
        );
    }

    // ── Execution ────────────────────────────────────────

    private capture(
        command: string,
        cancellationToken: vscode.CancellationToken
    ): Promise<ExecutionResult> {
        const type    = this.classifyCommand(command);
        const timeout = this.getTimeout(type);
        const prepared = this.prepareForCapture(command, type);

        return new Promise((resolve, reject) => {
            const proc = cp.exec(
                prepared,
                { timeout, maxBuffer: CommandExecutor.MAX_BUFFER },
                (error, stdout, stderr) => {
                    let exitCode = 0;
                    let stderrStr = stderr.trim();

                    if (error) {
                        exitCode = typeof error.code === 'number' ? error.code : 1;
                        if (error.killed) {
                            // Process was killed — either by our timeout or an external signal.
                            stderrStr = `${stderrStr}\n[Process terminated — exceeded ${timeout / 1000}s timeout]`.trim();
                        }
                        CloakdLogger.warn('Command completed with execution error.', {
                            exitCode,
                            timeoutMs: timeout,
                        });
                    }

                    resolve({
                        stdout: stdout.trim(),
                        stderr: stderrStr,
                        exitCode,
                    });
                }
            );

            // Close stdin immediately — we never send interactive input via exec.
            proc.stdin?.end();

            const cancelDisposable = cancellationToken.onCancellationRequested(() => {
                proc.kill();
                cancelDisposable.dispose();
                CloakdLogger.warn('Command cancelled by user or model cancellation token.');
                reject(new Error('Command cancelled.'));
            });

            proc.on('error', (err) => {
                cancelDisposable.dispose();
                reject(err);
            });
        });
    }

    // ── Terminal management ──────────────────────────────

    private ensureTerminal(): void {
        if (!this.terminal || this.terminal.exitStatus !== undefined) {
            this.terminal = vscode.window.createTerminal('Cloakd');
        }
    }

    private detectInteractiveReason(command: string): string | undefined {
        const trimmed = command.trim();

        const checks: Array<{ pattern: RegExp; reason: string }> = [
            { pattern: /^(?:\S+=\S+\s+)*sudo\b/i, reason: 'sudo often requests a password' },
            { pattern: /^(?:\S+=\S+\s+)*ssh\b/i, reason: 'ssh may require host-key or password confirmation' },
            { pattern: /^(?:\S+=\S+\s+)*sftp\b/i, reason: 'sftp sessions are interactive by design' },
            { pattern: /\b(read|select)\b/i, reason: 'shell read/select expects stdin input' },
            { pattern: /\b(passwd|mysql\s+-p|psql\s+[^\n]*-W)\b/i, reason: 'database/account tooling requests secure prompts' },
            { pattern: /\b(tail\s+-f|watch\b|less\b|vim\b|nano\b)\b/i, reason: 'command is long-running or interactive' },
            { pattern: /\b(git\s+(push|pull|fetch|clone))\b/i, reason: 'git may request credentials or host confirmation' },
            { pattern: /\b(docker\s+exec\s+-it|kubectl\s+exec\s+-it|kubectl\s+attach|kubectl\s+port-forward)\b/i, reason: 'tty/interactive session requested' },
        ];

        for (const check of checks) {
            if (check.pattern.test(trimmed)) {
                return check.reason;
            }
        }

        return undefined;
    }

    // ── Anonymization helpers ────────────────────────────

    /** Replace anonymized tokens with real values (longest-first). */
    public deAnonymize(text: string): string {
        const reverse = this.tokenManager.getReverseMappings();
        const sorted = [...reverse.keys()].sort((a, b) => b.length - a.length);

        let result = text;
        for (const token of sorted) {
            const original = reverse.get(token)!;
            result = result.replace(new RegExp(this.escapeRegex(token), 'g'), original);
        }
        return result;
    }

    /** Replace real values with tokens in command output before returning to model. */
    public reAnonymize(text: string): string {
        if (!text) { return text; }

        const forward = this.tokenManager.getAllMappings();
        const sorted = [...forward.keys()].sort((a, b) => b.length - a.length);

        let result = text;
        for (const original of sorted) {
            const token = forward.get(original)!;
            result = result.replace(new RegExp(this.escapeRegex(original), 'g'), token);
        }
        return result;
    }

    private escapeRegex(str: string): string {
        return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }

    // ── Cleanup ──────────────────────────────────────────

    /**
     * Clean up SSH ControlMaster sockets (Unix only).
     * Called when the extension is deactivated.
     * Sockets also auto-expire after SSH_CONTROL_PERSIST_SECS of inactivity.
     */
    public dispose(): void {
        if (process.platform === 'win32') { return; }

        try {
            const controlPattern = path.join(os.tmpdir(), 'cloakd_ssh_*');
            cp.execSync(`rm -f ${controlPattern}`, { timeout: 5_000 });
        } catch {
            // Best-effort — sockets will auto-expire via ControlPersist anyway.
        }
    }
}
