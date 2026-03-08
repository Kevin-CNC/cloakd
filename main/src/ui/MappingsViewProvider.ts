import * as vscode from 'vscode';
import { TokenManager } from '../anonymizer/TokenManager';

export class MappingsViewProvider implements vscode.TreeDataProvider<MappingItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<MappingItem | undefined | null> = 
        new vscode.EventEmitter<MappingItem | undefined | null>();
    readonly onDidChangeTreeData: vscode.Event<MappingItem | undefined | null> = 
        this._onDidChangeTreeData.event;

    constructor(private tokenManager: TokenManager) {}

    refresh(): void {
        this._onDidChangeTreeData.fire(undefined);
    }

    getTreeItem(element: MappingItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: MappingItem): Thenable<MappingItem[]> {
        if (element) {
            // No children below leaf items
            return Promise.resolve([]);
        }

        // Root level: list all token → original mappings
        const mappings = this.tokenManager.getAllMappings();
        const items: MappingItem[] = [];

        for (const [original, token] of mappings) {
            items.push(new MappingItem(
                token,
                original,
                vscode.TreeItemCollapsibleState.None
            ));
        }

        if (items.length === 0) {
            return Promise.resolve([
                new MappingItem('No mappings yet', 'Use @Cloakd to create mappings', vscode.TreeItemCollapsibleState.None)
            ]);
        }

        return Promise.resolve(items);
    }
}

export class MappingItem extends vscode.TreeItem {
    constructor(
        public readonly token: string,
        public readonly originalValue: string,
        public readonly collapsibleState: vscode.TreeItemCollapsibleState
    ) {
        super(token, collapsibleState);
        this.tooltip = `${token} → ${originalValue}`;
        this.description = originalValue;
        this.contextValue = 'mapping';
    }
}
