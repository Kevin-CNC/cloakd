import { SecretDetection } from '../ScannerTypes';

function escapeRegex(s: string): string {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function toConfidenceLevel(c: number): 'high' | 'medium' | 'low' {
    if (c >= 0.8) return 'high';
    if (c >= 0.55) return 'medium';
    return 'low';
}

function shannonEntropy(str: string): number {
    if (str.length === 0) return 0;

    const freq = new Map<string, number>();
    for (const ch of str) {
        freq.set(ch, (freq.get(ch) ?? 0) + 1);
    }

    let entropy = 0;
    for (const count of freq.values()) {
        const p = count / str.length;
        entropy -= p * Math.log2(p);
    }

    return entropy;
}

function charClassDiversity(str: string): number {
    let classes = 0;
    if (/[a-z]/.test(str)) classes++;
    if (/[A-Z]/.test(str)) classes++;
    if (/[0-9]/.test(str)) classes++;
    if (/[^a-zA-Z0-9]/.test(str)) classes++;
    return classes;
}

interface DetectorPattern {
    label: string;
    regex: RegExp;
    group: number;
    replacement: string;
    confidence: number;
    fileTypes?: string[];
    minLength?: number;
    blocklist?: Set<string>;
    validator?: (value: string, match: RegExpExecArray) => boolean;
}

const GENERIC_VALUE_BLOCKLIST = new Set([
    'password', 'pass', 'secret', 'token', 'api_key', 'apikey',
    'changeme', 'example', 'sample', 'default', 'test', 'testing',
    'admin', 'root', 'postgres', 'mysql', 'placeholder', 'replace_me',
    'your_password', 'your_secret', 'your_token', 'dummy', 'todo', 'fixme',
    'none', 'null', 'undefined', 'true', 'false', 'yes', 'no', 'abc123',
]);

const INFRASTRUCTURE_VALUE_PATTERNS = [
    /^(?:\d{1,3}\.){3}\d{1,3}$/,
    /^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/,
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/,
    /^arn:/i,
    /^(?:https?:\/\/|ftp:\/\/|file:\/\/)/i,
    /^(?:~\/|\/|\.\/|\.\.\/).+/,
    /^(?:var|local|module|data|path|process\.env|env)\./i,
    /^\$\{[^}]+\}$/,
    /^\$\{\{[^}]+\}\}$/,
    /^[a-z]+-[a-z0-9-]+-\d+$/i,
];

function looksLikeInfrastructureValue(value: string): boolean {
    const trimmed = value.trim();
    return INFRASTRUCTURE_VALUE_PATTERNS.some(pattern => pattern.test(trimmed));
}

function hasKnownSecretPrefix(value: string): boolean {
    return /^(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z\-_]{35}|xox[baprs]-[0-9A-Za-z-]{10,}|(?:sk|pk)_(?:live|test)_[0-9A-Za-z]{24,})$/.test(value);
}

function isLikelySecretValue(value: string, minLength = 8): boolean {
    const trimmed = value.trim();
    const lower = trimmed.toLowerCase();

    if (trimmed.length < minLength) {
        return false;
    }

    if (GENERIC_VALUE_BLOCKLIST.has(lower) || looksLikeInfrastructureValue(trimmed)) {
        return false;
    }

    if (/\s/.test(trimmed) && !/^-----BEGIN [A-Z ]+PRIVATE KEY-----/.test(trimmed)) {
        return false;
    }

    if (/^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(trimmed)) {
        return true;
    }

    if (hasKnownSecretPrefix(trimmed)) {
        return true;
    }

    const entropy = shannonEntropy(trimmed);
    const diversity = charClassDiversity(trimmed);
    const structuredToken = /^[A-Za-z0-9+/_=-]{16,}$/.test(trimmed);
    const longMixedToken = trimmed.length >= 20 && diversity >= 2 && /\d/.test(trimmed);

    if (structuredToken && entropy >= 3.2 && diversity >= 2) {
        return true;
    }

    if (longMixedToken && entropy >= 2.8) {
        return true;
    }

    return trimmed.length >= 24 && diversity >= 3 && entropy >= 2.6;
}

function isLikelyPasswordValue(value: string): boolean {
    if (isLikelySecretValue(value, 6)) {
        return true;
    }

    const trimmed = value.trim();
    const lower = trimmed.toLowerCase();
    if (GENERIC_VALUE_BLOCKLIST.has(lower) || looksLikeInfrastructureValue(trimmed)) {
        return false;
    }

    return trimmed.length >= 10 && charClassDiversity(trimmed) >= 2 && !/^[a-z]+$/i.test(trimmed);
}

function extractBearerPayload(value: string): string {
    return value.replace(/^Bearer\s+/i, '').trim();
}

const PATTERNS: DetectorPattern[] = [
    {
        label: 'AWS access key',
        regex: /\b(AKIA[0-9A-Z]{16})\b/g,
        group: 1,
        replacement: 'AWS_KEY',
        confidence: 0.95,
    },
    {
        label: 'GitHub token',
        regex: /\b((?:gh[pousr]_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{20,}))\b/g,
        group: 1,
        replacement: 'GITHUB_TOKEN',
        confidence: 0.95,
    },
    {
        label: 'OpenAI API key',
        regex: /\b(sk-[A-Za-z0-9_-]{20,})\b/g,
        group: 1,
        replacement: 'OPENAI_KEY',
        confidence: 0.90,
    },
    {
        label: 'Google API key',
        regex: /\b(AIza[0-9A-Za-z\-_]{35})\b/g,
        group: 1,
        replacement: 'GOOGLE_KEY',
        confidence: 0.90,
    },
    {
        label: 'Slack token',
        regex: /\b(xox[baprs]-[0-9A-Za-z-]{10,})\b/g,
        group: 1,
        replacement: 'SLACK_TOKEN',
        confidence: 0.90,
    },
    {
        label: 'Stripe API key',
        regex: /\b((?:sk|pk)_(?:live|test)_[0-9A-Za-z]{24,})\b/g,
        group: 1,
        replacement: 'STRIPE_KEY',
        confidence: 0.92,
    },
    {
        label: 'JWT token',
        regex: /\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g,
        group: 1,
        replacement: 'JWT_TOKEN',
        confidence: 0.88,
    },
    {
        label: 'Private key block',
        regex: /(-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----)/g,
        group: 1,
        replacement: 'PRIVATE_KEY',
        confidence: 0.95,
    },
    {
        label: 'Azure connection string with account key',
        regex: /\b(DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+;?[^\s"']*)/g,
        group: 1,
        replacement: 'AZURE_CONN',
        confidence: 0.92,
    },
    {
        label: 'Bearer token header',
        regex: /(?:Authorization|Bearer)\s*[:=]\s*["']?((?:Bearer\s+)?[A-Za-z0-9._\-+/=]{20,})["']?/gi,
        group: 1,
        replacement: 'AUTH_TOKEN',
        confidence: 0.84,
        validator: (value) => isLikelySecretValue(extractBearerPayload(value), 16),
    },
    {
        label: 'Hardcoded password assignment',
        regex: /["']?(?:password|passwd|pass|pwd)["']?\s*[:=]\s*["']([^"'\s${}]{6,})["']/gi,
        group: 1,
        replacement: 'PASSWORD',
        confidence: 0.74,
        minLength: 6,
        blocklist: GENERIC_VALUE_BLOCKLIST,
        validator: (value) => isLikelyPasswordValue(value),
    },
    {
        label: 'Hardcoded secret or token assignment',
        regex: /["']?(?:secret|token|api[_-]?key|auth[_-]?key|access[_-]?key|client[_-]?secret|webhook[_-]?secret|private[_-]?key)[A-Za-z0-9_-]*["']?\s*[:=]\s*["']([^"'\s${}]{8,})["']/gi,
        group: 1,
        replacement: 'SECRET',
        confidence: 0.80,
        minLength: 8,
        blocklist: GENERIC_VALUE_BLOCKLIST,
        validator: (value) => isLikelySecretValue(value, 8),
    },
    {
        label: 'Database connection string with embedded credentials',
        regex: /\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql):\/\/[^:\s"'<>\/@]+:[^@\s"'<>]{6,}@[^\s"'<>]+)\b/gi,
        group: 1,
        replacement: 'DB_CONN_STRING',
        confidence: 0.87,
    },
    {
        label: 'Dotenv secret variable',
        regex: /^(?:export\s+)?(?:SECRET|TOKEN|API_KEY|AUTH|PASSWORD|PASSWD|PRIVATE_KEY|ACCESS_KEY|CLIENT_SECRET)[A-Z_0-9]*\s*=\s*["']?([^\s"'#]{8,})["']?/gim,
        group: 1,
        replacement: 'ENV_SECRET',
        confidence: 0.84,
        fileTypes: ['dotenv', 'shell', 'generic'],
        minLength: 8,
        blocklist: GENERIC_VALUE_BLOCKLIST,
        validator: (value) => isLikelySecretValue(value, 8),
    },
];

export class RegexDetector {
    detect(content: string, fileType: string): SecretDetection[] {
        const results: SecretDetection[] = [];
        const seen = new Set<string>();
        const counters = new Map<string, number>();

        for (const pat of PATTERNS) {
            if (pat.fileTypes && pat.fileTypes.length > 0 && !pat.fileTypes.includes(fileType)) {
                continue;
            }

            pat.regex.lastIndex = 0;

            let m: RegExpExecArray | null;
            while ((m = pat.regex.exec(content)) !== null) {
                const value = (m[pat.group] ?? m[0]).trim();

                if (pat.minLength && value.length < pat.minLength) continue;
                if (pat.blocklist?.has(value.toLowerCase())) continue;
                if (pat.validator && !pat.validator(value, m)) continue;
                if (seen.has(value)) continue;
                seen.add(value);

                const count = (counters.get(pat.replacement) ?? 0) + 1;
                counters.set(pat.replacement, count);

                results.push({
                    value,
                    pattern: escapeRegex(value),
                    replacement: `${pat.replacement}_${count}`,
                    description: pat.label,
                    confidence: pat.confidence,
                    source: 'regex',
                    confidenceLevel: toConfidenceLevel(pat.confidence),
                });
            }
        }

        return results;
    }
}
