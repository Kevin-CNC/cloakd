import * as assert from 'assert';
import * as vscode from 'vscode';

suite('Cloakd Extension Smoke Tests', () => {
    test('commands are registered', async () => {
        const commands = await vscode.commands.getCommands(true);

        const expectedCommands = [
            'cloakd.openUI',
            'cloakd.switchRulesheet',
            'cloakd.quickAddRule',
        ];

        for (const command of expectedCommands) {
            assert.ok(commands.includes(command), `Expected command to be registered: ${command}`);
        }
    });
});
