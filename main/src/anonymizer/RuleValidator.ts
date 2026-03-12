import { AnonymizationRule } from './PatternLibrary';
import { compilePattern } from './patternMatcher';

export interface RuleValidationResult {
    valid: boolean;
    errors: string[];
    warnings: string[];
}

const TOKEN_REPLACEMENT_PATTERN = /^[A-Za-z][A-Za-z0-9_@:\-./{}]*$/;

const OVERLAP_PROBES = [
    '10.20.30.40',
    '2001:db8:85a3::8a2e:370:7334',
    'admin@example.com',
    '123e4567-e89b-12d3-a456-426614174000',
    'AKIAIOSFODNN7EXAMPLE',
    'ghp_abcdefghijklmnopqrstuvwxyz1234567890',
    'sk-abc123xyz456def789ghi012jkl345mno678',
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTYifQ.signature',
    '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcw\n-----END PRIVATE KEY-----',
    '/home/ubuntu/.ssh/id_rsa',
    '/etc/kubernetes/pki/apiserver.key',
    'dbPassword',
    'client_secret'
];

function compileRegex(pattern: string): RegExp {
    return compilePattern(pattern);
}

function isRuleEmpty(rule: Pick<AnonymizationRule, 'pattern' | 'replacement'>): boolean {
    const pattern = typeof rule.pattern === 'string' ? rule.pattern.trim() : rule.pattern.source.trim();
    const replacement = rule.replacement?.trim() ?? '';
    return pattern.length === 0 && replacement.length === 0;
}

function extractLiteralHints(pattern: string): string[] {
    const tokenHints = pattern
        .replace(/\\[dDsSwWbB]/g, ' ')
        .replace(/[()[\]{}.*+?|^$\\]/g, ' ')
        .split(/\s+/)
        .map(t => t.trim())
        .filter(t => t.length >= 4);

    return Array.from(new Set(tokenHints)).slice(0, 6);
}

function maybeOverlappingRegex(leftPattern: string, rightPattern: string): boolean {
    if (leftPattern === rightPattern) {
        return true;
    }

    if (leftPattern.includes(rightPattern) || rightPattern.includes(leftPattern)) {
        return true;
    }

    let leftRegex: RegExp;
    let rightRegex: RegExp;

    try {
        leftRegex = compileRegex(leftPattern);
        rightRegex = compileRegex(rightPattern);
    } catch {
        return false;
    }

    const probeSet = new Set<string>(OVERLAP_PROBES);
    for (const hint of extractLiteralHints(leftPattern)) {
        probeSet.add(hint);
    }
    for (const hint of extractLiteralHints(rightPattern)) {
        probeSet.add(hint);
    }

    for (const sample of probeSet) {
        leftRegex.lastIndex = 0;
        rightRegex.lastIndex = 0;

        if (leftRegex.test(sample) && rightRegex.test(sample)) {
            return true;
        }
    }

    return false;
}

export function validateRules(rules: AnonymizationRule[]): RuleValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    const activeRules = rules.filter(rule => rule.enabled !== false && !isRuleEmpty(rule));

    const normalizedRules = activeRules.map(rule => ({
        id: rule.id,
        pattern: typeof rule.pattern === 'string' ? rule.pattern.trim() : rule.pattern.source.trim(),
        replacement: (rule.replacement ?? '').trim(),
    }));

    for (let i = 0; i < normalizedRules.length; i++) {
        const rule = normalizedRules[i];
        const displayIndex = i + 1;

        if (!rule.pattern) {
            errors.push(`Rule ${displayIndex}: pattern is required.`);
            continue;
        }

        if (!rule.replacement) {
            errors.push(`Rule ${displayIndex}: replacement is required.`);
        } else if (!TOKEN_REPLACEMENT_PATTERN.test(rule.replacement)) {
            errors.push(`Rule ${displayIndex}: replacement "${rule.replacement}" is invalid. Use a token-like label (letters, digits, _, -, :, @, ., /, and optional {index}).`);
        }

        try {
            compileRegex(rule.pattern);
        } catch (error) {
            errors.push(`Rule ${displayIndex}: invalid regex "${rule.pattern}" (${error instanceof Error ? error.message : 'unknown error'}).`);
        }
    }

    const seenPatternToRule = new Map<string, { id: string; replacement: string; index: number }>();

    for (let i = 0; i < normalizedRules.length; i++) {
        const rule = normalizedRules[i];
        const existing = seenPatternToRule.get(rule.pattern);
        if (!existing) {
            seenPatternToRule.set(rule.pattern, { id: rule.id, replacement: rule.replacement, index: i + 1 });
            continue;
        }

        if (existing.replacement !== rule.replacement) {
            errors.push(
                `Conflicting rules: Rule ${existing.index} and Rule ${i + 1} share pattern "${rule.pattern}" but use different replacements ("${existing.replacement}" vs "${rule.replacement}").`
            );
        } else {
            warnings.push(
                `Duplicate rules: Rule ${existing.index} and Rule ${i + 1} both match "${rule.pattern}" and map to "${rule.replacement}".`
            );
        }
    }

    for (let i = 0; i < normalizedRules.length; i++) {
        for (let j = i + 1; j < normalizedRules.length; j++) {
            const left = normalizedRules[i];
            const right = normalizedRules[j];

            if (left.pattern === right.pattern) {
                continue;
            }

            if (maybeOverlappingRegex(left.pattern, right.pattern)) {
                warnings.push(
                    `Potential overlap: Rule ${i + 1} ("${left.pattern}") may overlap Rule ${j + 1} ("${right.pattern}").`
                );
            }
        }
    }

    return {
        valid: errors.length === 0,
        errors: Array.from(new Set(errors)),
        warnings: Array.from(new Set(warnings)),
    };
}
