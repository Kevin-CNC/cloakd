import * as assert from 'assert';
import { ToolOutputSanitizer } from '../../tools/ToolOutputSanitizer';
import { ToolPolicyEngine } from '../../tools/ToolPolicy';
import { WrappedToolRegistry } from '../../tools/WrappedToolRegistry';

suite('Wrapped Tool Registry', () => {
    test('creates wrapped aliases for non-Cloakd tools', () => {
        const tools = [
            { name: 'cloakd_execute_command', description: 'native', inputSchema: {} },
            { name: 'filesystem.read', description: 'external', inputSchema: {} },
        ];

        const registry = new WrappedToolRegistry(tools, {
            shouldWrapTool: (toolName: string) => !toolName.startsWith('cloakd_'),
        });

        const wrappedDefs = registry.getWrappedToolDefinitions();
        assert.strictEqual(wrappedDefs.length, 1);
        assert.ok(wrappedDefs[0].name.startsWith('cloakd_wrap_'));
        assert.strictEqual(registry.resolveOriginalName(wrappedDefs[0].name), 'filesystem.read');
        assert.strictEqual(registry.resolveWrappedName('filesystem.read'), wrappedDefs[0].name);
    });
});

suite('Tool Policy Engine', () => {
    test('tokenOnly preserves tool input values', () => {
        const engine = new ToolPolicyEngine();
        const policy = engine.resolvePolicy('unknown_tool');
        const input = { secret: 'TOKEN_1' };

        const transformed = engine.prepareInputForInvocation(input, policy, (value) => value.replace('TOKEN_1', 'REAL_SECRET'));
        assert.deepStrictEqual(transformed, input);
    });

    test('selectiveDeanonymize only de-anonymizes allowed paths', () => {
        const engine = new ToolPolicyEngine({
            perTool: {
                externalTool: {
                    mode: 'selectiveDeanonymize',
                    allowedInputPaths: ['credentials.password'],
                    allowExternal: true,
                },
            },
        });

        const policy = engine.resolvePolicy('externalTool');
        const input = {
            credentials: {
                password: 'TOKEN_PASS',
                user: 'TOKEN_USER',
            },
        };

        const transformed = engine.prepareInputForInvocation(input, policy, (value) => value.replace('TOKEN_', 'REAL_')) as {
            credentials: { password: string; user: string };
        };

        assert.strictEqual(transformed.credentials.password, 'REAL_PASS');
        assert.strictEqual(transformed.credentials.user, 'TOKEN_USER');
    });
});

suite('Tool Output Sanitizer', () => {
    test('re-anonymizes and truncates string results', () => {
        const sanitizer = new ToolOutputSanitizer();
        const safeParts = sanitizer.sanitizeToolContent(
            ['REAL_SECRET plus additional output that should be trimmed'],
            (value) => value.replace('REAL_SECRET', 'TOKEN_1'),
            { maxOutputSize: 18 }
        );

        assert.strictEqual(typeof safeParts[0], 'string');
        const text = String(safeParts[0]);
        assert.ok(text.includes('TOKEN_1'));
        assert.ok(text.includes('[truncated by Cloakd output policy]'));
    });
});
