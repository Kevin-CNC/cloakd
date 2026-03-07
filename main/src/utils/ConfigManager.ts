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

    constructor(ruleFilePath: string) {
        this.configFilePath = ruleFilePath;
    }

    setConfigFilePath(ruleFilePath: string): void {
        this.configFilePath = ruleFilePath;
    }

    getConfigFilePath(): string {
        return this.configFilePath;
    }

    loadConfig(): ProjectConfig {
        try {
            if (!this.rulesheetExists(this.configFilePath)) {
                return this.getDefaultConfig();
            }
            const content = fs.readFileSync(this.configFilePath, 'utf-8');
            const config = JSON.parse(content) as ProjectConfig;
            if (!this.isActuallyWellParsed(config)) {
                return this.getDefaultConfig();
            }
            return config;
        } catch (error) {
            console.error("Error loading config:", error);
            CloakdLogger.error('Failed to load Cloakd config.', {
                filePath: this.configFilePath,
                reason: error instanceof Error ? error.message : String(error),
            });
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
        return this.loadConfig().rules
            .filter(rule => rule.enabled)
            .map(rule => ({
                // Safely convert string | RegExp to string
                pattern: typeof rule.pattern === 'string'
                    ? rule.pattern
                    : (rule.pattern as RegExp).source,
                replacement: rule.replacement
            }));
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
            const content = fs.readFileSync(this.configFilePath, 'utf-8');
            const config = JSON.parse(content) as ProjectConfig;
            if (!this.isActuallyWellParsed(config)) { return null; }
            return config;
        } catch {
            return null;
        }
    }

}
