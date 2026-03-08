import * as vscode from 'vscode';

export class TokenManager {
    private mappings: Map<string, string> = new Map(); // original -> token
    private reverseMappings: Map<string, string> = new Map(); // token -> original
    private counters: Map<string, number> = new Map(); // type -> count
    private context: vscode.ExtensionContext;

    constructor(context: vscode.ExtensionContext) {
        this.context = context;
        this.loadMappings();
    }
    generateToken(type: string, originalValue: string): string {
        // Check if value already has a token (for consistency)
        const existing = this.mappings.get(originalValue);
        if (existing) {
            return existing;
        }

        // Get or initialize counter for this type
        const count = (this.counters.get(type) || 0) + 1;
        this.counters.set(type, count);

        // Generate a new unique token from the supplied template/type
        let token = this.formatToken(type, count);
        while (this.reverseMappings.has(token)) {
            const nextCount = (this.counters.get(type) || count) + 1;
            this.counters.set(type, nextCount);
            token = this.formatToken(type, nextCount);
        }

        // Store bidirectional mapping
        this.mappings.set(originalValue, token);
        this.reverseMappings.set(token, originalValue);

        // Persist to VS Code's workspace state
        this.saveMappings();
        
        return token;
    }

    storeMapping(originalValue: string, token: string): void {
        // If the original value was previously mapped to a DIFFERENT token, remove
        // the stale reverse entry so deAnonymize never resolves an outdated name.
        const previousToken = this.mappings.get(originalValue);
        if (previousToken !== undefined && previousToken !== token) {
            this.reverseMappings.delete(previousToken);
        }

        this.mappings.set(originalValue, token);
        this.reverseMappings.set(token, originalValue);
        this.saveMappings();
    }

    private formatToken(type: string, index: number): string {
        if (type.includes('{index}')) {
            return type.replace(/\{index\}/g, String(index));
        }

        // Backward-compatible formatting for built-in type names
        switch(type.toLowerCase()) {
            case 'ip':
                return `IP_${index}`;
            case 'email':
                return `USER_${String.fromCharCode(64 + index)}@domain.tld`;
            case 'api-key':
                return `API_KEY_${index}`;
            case 'uuid':
                return `UUID_${index}`;
            case 'secret':
                return `SECRET_${index}`;
            case 'jwt':
                return `JWT_TOKEN_${index}`;
            case 'private-key':
                return `PRIVATE_KEY_${index}`;
            case 'path':
                return `/PATH_${index}`;
            default:
                // Custom replacement labels are used as-is.
                // Add a suffix only when multiple distinct values share the same label.
                return index > 1 ? `${type}_${index}` : type;
        }
    }

    getOriginalValue(token: string): string | undefined {
        return this.reverseMappings.get(token);
    }

    getAllMappings(): Map<string, string> {
        return new Map(this.mappings);
    }

    /**
     * Returns the token→original reverse mapping.
     * Used by CommandExecutor to de-anonymize commands before terminal execution.
     * The returned map is read-only — mutations have no effect on internal state.
     */
    getReverseMappings(): ReadonlyMap<string, string> {
        return this.reverseMappings;
    }

    clearMappings(): void {
        this.mappings.clear();
        this.reverseMappings.clear();
        this.counters.clear();
        this.saveMappings();
    }

    private saveMappings(): void {
        // Persist mappings to VS Code workspace state
        const mappingsArray = Array.from(this.mappings.entries());
        const countersArray = Array.from(this.counters.entries());
        
        this.context.workspaceState.update('cloakd.mappings', mappingsArray);
        this.context.workspaceState.update('cloakd.counters', countersArray);
    }

    private loadMappings(): void {
        // Load mappings from VS Code workspace state
        const mappingsArray = this.context.workspaceState.get<Array<[string, string]>>('cloakd.mappings', []);
        const countersArray = this.context.workspaceState.get<Array<[string, number]>>('cloakd.counters', []);
        
        this.mappings = new Map(mappingsArray);
        this.counters = new Map(countersArray);
        
        // Rebuild reverse mappings
        this.reverseMappings.clear();
        for (const [original, token] of this.mappings) {
            this.reverseMappings.set(token, original);
        }
    }
}
