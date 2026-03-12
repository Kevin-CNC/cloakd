import * as assert from 'assert';
import * as vscode from 'vscode';

suite('Cloakd Extension Smoke Tests', () => {
    test('commands are contributed and registered after activation', async () => {
        const extension = vscode.extensions.getExtension('kevincncaplescu.cloakd');
        assert.ok(extension, 'Expected Cloakd extension to be installed in test host.');

        const expectedCommands = [
            'cloakd.openUI',
            'cloakd.switchRulesheet',
            'cloakd.quickAddRule',
            'cloakd.scanCurrentFile',
            'cloakd.scanSecrets',
        ];
        const contributed = (extension!.packageJSON?.contributes?.commands ?? []) as Array<{ command: string }>;

        for (const command of expectedCommands) {
            assert.ok(
                contributed.some(item => item.command === command),
                `Expected command to be contributed in package manifest: ${command}`
            );
        }

        await extension!.activate();

        const runtimeCommands = await vscode.commands.getCommands(true);
        for (const command of expectedCommands) {
            assert.ok(runtimeCommands.includes(command), `Expected command to be registered after activation: ${command}`);
        }
    });
});
