import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { AnonymizationRule } from '../anonymizer/PatternLibrary';
import { CloakdLogger } from './CloakdLogger';

export interface ProjectConfig {
    version: string;
    enabled: boolean;
    rules: AnonymizationRule[];
    tokenConsistency: boolean;
    autoAnonymize: boolean;
    showPreview: boolean;
}

export class ConfigManager {
    private configFilePath: string;
    private cachedConfig: ProjectConfig | undefined;
    private cachedConfigMtimeMs: number | undefined;
    private cachedRules: Array<{ pattern: string; replacement: string }> | undefined;
    private cachedRulesMtimeMs: number | undefined;

    constructor(ruleFilePath: string) {
        this.configFilePath = ruleFilePath;
    }

    setConfigFilePath(ruleFilePath: string): void {
        if (this.configFilePath !== ruleFilePath) {
            this.invalidateCaches();
        }
        this.configFilePath = ruleFilePath;
    }

    getConfigFilePath(): string {
        return this.configFilePath;
    }

    loadConfig(): ProjectConfig {
        try {
            if (!this.rulesheetExists(this.configFilePath)) {
                this.invalidateCaches();
                return this.getDefaultConfig();
            }

            const mtimeMs = this.getRulesheetMtimeMs();
            if (
                this.cachedConfig &&
                this.cachedConfigMtimeMs !== undefined &&
                mtimeMs !== undefined &&
                this.cachedConfigMtimeMs === mtimeMs
            ) {
                return this.cloneConfig(this.cachedConfig);
            }

            const content = fs.readFileSync(this.configFilePath, 'utf-8');
            const config = JSON.parse(content) as ProjectConfig;
            if (!this.isActuallyWellParsed(config)) {
                return this.getDefaultConfig();
            }

            this.cachedConfig = this.cloneConfig(config);
            this.cachedConfigMtimeMs = mtimeMs;
            return this.cloneConfig(config);
        } catch (error) {
            console.error("Error loading config:", error);
            CloakdLogger.error('Failed to load Cloakd config.', {
                filePath: this.configFilePath,
                reason: error instanceof Error ? error.message : String(error),
            });
            this.invalidateCaches();
            return this.getDefaultConfig();
        }
    }

    private getDefaultConfig(): ProjectConfig {
        return {
            version: "0",
            enabled: false,
            rules: [],
            tokenConsistency: false,
            autoAnonymize: false,
            showPreview: true
        };
    }

    // helper for getting the workspace root path
    private getWorkspacePth(): string{
        const workspace = vscode.workspace.workspaceFolders;

        if ( workspace === undefined || workspace.length === 0){
            throw new Error('No workspace folder open');
        }

        return workspace[0].uri.fsPath;
    }


    private rulesheetExists(pathOfRulesheet:string): boolean{
        return fs.existsSync(pathOfRulesheet);
    }

    private isActuallyWellParsed(rules: ProjectConfig): rules is ProjectConfig {
        // checks if the basic structure of the config is correct.

        return typeof rules === 'object'
        && typeof rules.version === 'string'
        && typeof rules.enabled === 'boolean'
        && Array.isArray(rules.rules)
        && typeof rules.tokenConsistency === 'boolean'
        && typeof rules.autoAnonymize === 'boolean'
        && typeof rules.showPreview === 'boolean';
    }


    async loadProjectRules(): Promise<AnonymizationRule[]> {
        try{
            // before anything, check if the rulesheet actually exists.
            if(!this.rulesheetExists(this.configFilePath)){
                console.log(`Config file not found at ${this.configFilePath}`);
                return [];
            }

            let content = fs.readFileSync(this.configFilePath, 'utf-8');

            // parse the content and return the configs object after checking if it's valid.
            let config: ProjectConfig = JSON.parse(content);

            if (!this.isActuallyWellParsed(config)){ // The structure is invalid? Notify the user later
                console.error("Config file structure is invalid:", config);
                throw new Error('Config file structure is invalid');
            }

            return config.rules || [];

        }catch(error){
            console.error("Error loading project rules:", error);
            CloakdLogger.error('Failed to load project rules.', {
                filePath: this.configFilePath,
                reason: error instanceof Error ? error.message : String(error),
            });
            return [];
        }
    }

    async saveProjectRules(rules: AnonymizationRule[]): Promise<void> {
        try{
            // before anything, check if the rulesheet actually exists.
            if(!this.rulesheetExists(this.configFilePath)){
                console.log(`Config file not found at ${this.configFilePath}`);
                throw new Error('Config file not found!');
            }


            // insert the new rules into the existing config structure, then write it back to the file.
            let currentContent = fs.readFileSync(this.configFilePath, 'utf-8');
            let newConfig = JSON.parse(currentContent) as ProjectConfig;
            
            if (this.isActuallyWellParsed(newConfig)){ // Check for structure integrity & then apply
                newConfig.rules = rules;
                fs.writeFileSync(this.configFilePath, JSON.stringify(newConfig, null, 2), 'utf-8');
                this.invalidateCaches();
                vscode.window.showInformationMessage(`New configs have been applied!`);
            }else{
                throw new Error('Parsed structure of config file is invalid, cannot apply new rules');
            }


        }catch(error){
            console.error("Error saving project rules:", error);
            CloakdLogger.error('Failed to save project rules.', {
                filePath: this.configFilePath,
                reason: error instanceof Error ? error.message : String(error),
            });
            this.invalidateCaches();
            vscode.window.showInformationMessage(`An error occurred while saving your new rules.`);
        }
    }

    async initializeProjectConfig(): Promise<void> {
        // TODO: Create default .cloakd.json in workspace root
        // 1. Check workspace exists
        // 2. Check file doesn't already exist
        // 3. Create with default config structure
    }

    getRules(): Array<{ pattern: string; replacement: string }> {
        if (!this.rulesheetExists(this.configFilePath)) {
            this.cachedRules = [];
            this.cachedRulesMtimeMs = undefined;
            return [];
        }

        const mtimeMs = this.getRulesheetMtimeMs();
        if (
            this.cachedRules &&
            this.cachedRulesMtimeMs !== undefined &&
            mtimeMs !== undefined &&
            this.cachedRulesMtimeMs === mtimeMs
        ) {
            return [...this.cachedRules];
        }

        const nextRules = this.loadConfig().rules
            .filter(rule => rule.enabled)
            .map(rule => ({
                pattern: typeof rule.pattern === 'string'
                    ? rule.pattern
                    : (rule.pattern as RegExp).source,
                replacement: rule.replacement
            }));

        this.cachedRules = nextRules;
        this.cachedRulesMtimeMs = mtimeMs;
        return [...nextRules];
    }

    // ---- Helpers for the webview UI ----

    getRulesheetName(): string {
        return path.basename(this.configFilePath, '.cloakd.json');
    }

    getWorkspaceFolderName(): string {
        const folder = vscode.workspace.getWorkspaceFolder(vscode.Uri.file(this.configFilePath));
        return folder?.name ?? 'Unknown Workspace';
    }

    async loadFullConfig(): Promise<ProjectConfig | null> {
        try {
            if (!this.rulesheetExists(this.configFilePath)) { return null; }
            const config = this.loadConfig();
            if (!this.isActuallyWellParsed(config)) { return null; }
            return this.cloneConfig(config);
        } catch {
            return null;
        }
    }

    getRulesCacheFingerprint(): string {
        const mtimeMs = this.getRulesheetMtimeMs();
        return `${this.configFilePath}:${mtimeMs ?? 'missing'}`;
    }

    invalidateCaches(): void {
        this.cachedConfig = undefined;
        this.cachedConfigMtimeMs = undefined;
        this.cachedRules = undefined;
        this.cachedRulesMtimeMs = undefined;
    }

    private cloneConfig(config: ProjectConfig): ProjectConfig {
        return {
            ...config,
            rules: [...config.rules],
        };
    }

    private getRulesheetMtimeMs(): number | undefined {
        try {
            if (!this.rulesheetExists(this.configFilePath)) {
                return undefined;
            }
            return fs.statSync(this.configFilePath).mtimeMs;
        } catch {
            return undefined;
        }
    }

}
