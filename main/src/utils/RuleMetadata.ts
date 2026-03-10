import { AnonymizationRule } from '../anonymizer/PatternLibrary';

const RULE_TYPES = ['ip', 'email', 'uuid', 'secret', 'api-key', 'path', 'jwt', 'private-key', 'custom'] as const;

export type RuleType = (typeof RULE_TYPES)[number];

export interface WebviewRule {
    id: string;
    pattern: string;
    replacement: string;
    type: RuleType;
    enabled: boolean;
    description: string;
}

function isRuleType(value: unknown): value is RuleType {
    return typeof value === 'string' && RULE_TYPES.includes(value as RuleType);
}

function toPatternString(value: unknown): string {
    if (typeof value === 'string') {
        return value;
    }
    if (value instanceof RegExp) {
        return value.source;
    }
    if (typeof value === 'object' && value !== null && 'source' in value) {
        const source = (value as { source?: unknown }).source;
        return typeof source === 'string' ? source : '';
    }
    return '';
}

function toRuleId(value: unknown): string {
    if (typeof value === 'string' && value.trim().length > 0) {
        return value;
    }
    return `rule_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

export function toWebviewRule(rule: Partial<AnonymizationRule>): WebviewRule {
    return {
        id: toRuleId(rule.id),
        pattern: toPatternString(rule.pattern),
        replacement: typeof rule.replacement === 'string' ? rule.replacement : '',
        type: isRuleType(rule.type) ? rule.type : 'custom',
        enabled: typeof rule.enabled === 'boolean' ? rule.enabled : true,
        description: typeof rule.description === 'string' ? rule.description : '',
    };
}

export function normalizeRuleForStorage(
    incoming: Partial<WebviewRule>,
    existing?: Partial<AnonymizationRule>
): AnonymizationRule {
    const fallback = existing ?? {};
    return {
        id: toRuleId(incoming.id ?? fallback.id),
        pattern: toPatternString(incoming.pattern ?? fallback.pattern),
        replacement: typeof incoming.replacement === 'string'
            ? incoming.replacement
            : (typeof fallback.replacement === 'string' ? fallback.replacement : ''),
        type: isRuleType(incoming.type)
            ? incoming.type
            : (isRuleType(fallback.type) ? fallback.type : 'custom'),
        enabled: typeof incoming.enabled === 'boolean'
            ? incoming.enabled
            : (typeof fallback.enabled === 'boolean' ? fallback.enabled : true),
        description: typeof incoming.description === 'string'
            ? incoming.description
            : (typeof fallback.description === 'string' ? fallback.description : ''),
    };
}

export function normalizeRulesForStorage(
    incomingRules: Array<Partial<WebviewRule>>,
    existingRules: AnonymizationRule[] = []
): AnonymizationRule[] {
    const existingById = new Map(existingRules.map(rule => [rule.id, rule]));
    return (incomingRules ?? []).map((rule) => {
        const candidateId = typeof rule.id === 'string' ? rule.id : '';
        const existing = candidateId ? existingById.get(candidateId) : undefined;
        return normalizeRuleForStorage(rule, existing);
    });
}

export function normalizeImportedRules(sourceRules: unknown[]): WebviewRule[] {
    return (sourceRules ?? [])
        .map((rule) => toWebviewRule((rule ?? {}) as Partial<AnonymizationRule>))
        .filter((rule) => rule.pattern.trim().length > 0 || rule.replacement.trim().length > 0);
}

export function exportableRules(rules: Array<Partial<WebviewRule>>): WebviewRule[] {
    return (rules ?? [])
        .map((rule) => toWebviewRule(rule as Partial<AnonymizationRule>))
        .filter((rule) => rule.pattern.trim().length > 0 || rule.replacement.trim().length > 0);
}
