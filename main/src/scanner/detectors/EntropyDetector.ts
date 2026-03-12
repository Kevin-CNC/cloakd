import { ConfidenceLevel, SecretDetection } from '../ScannerTypes';

function escapeRegex(s: string): string {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function toConfidenceLevel(c: number): ConfidenceLevel {
    if (c >= 0.8) return 'high';
    if (c >= 0.55) return 'medium';
    return 'low';
}

/**
 * Calculate Shannon entropy of a string in bits per character.
 * Higher entropy indicates more randomness (likely a secret).
 */
function shannonEntropy(str: string): number {
    if (str.length === 0) return 0;

    const freq = new Map<string, number>();
    for (const ch of str) {
        freq.set(ch, (freq.get(ch) ?? 0) + 1);
    }

    let entropy = 0;
    const len = str.length;
    for (const count of freq.values()) {
        const p = count / len;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}

/**
 * Character class diversity: how many distinct character classes appear.
 * Classes: uppercase, lowercase, digit, special.
 * A high-entropy secret typically has 3–4 classes.
 */
function charClassDiversity(str: string): number {
    let classes = 0;
    if (/[a-z]/.test(str)) classes++;
    if (/[A-Z]/.test(str)) classes++;
    if (/[0-9]/.test(str)) classes++;
    if (/[^a-zA-Z0-9]/.test(str)) classes++;
    return classes;
}

const ENTROPY_BLOCKLIST = new Set([
    'abcdefghijklmnopqrstuvwxyz',
    'abcdefghijklmnop',
    'lorem ipsum dolor sit amet',
    'the quick brown fox jumps over',
    '0000000000000000',
    '1111111111111111',
    '1234567890123456',
    'aaaaaaaaaaaaaaaa',
    'bbbbbbbbbbbbbbbb',
]);

const ENTROPY_SKIP_PATTERNS = [
    /^#[0-9a-fA-F]{6}$/,
    /^[0-9a-f]{7,8}$/,
    /^\d+$/,
    /^lorem/i,
    /^sha\d/i,
    /^md5/i,
    /^(?:\d{1,3}\.){3}\d{1,3}$/,
    /^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/,
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/,
    /^arn:/i,
    /^[a-z]+-[a-z0-9-]+-\d+$/i,
    /^(?:var|local|module|data|path|process\.env|env)\./i,
    /^\$\{[^}]+\}$/,
    /^\$\{\{[^}]+\}\}$/,
];

const SECRET_FIELD_NAME = /(secret|token|api[_-]?key|auth|password|passwd|private[_-]?key|client[_-]?secret|access[_-]?key|session|cookie|credential|webhook)/i;
const MIN_CONTEXTUAL_TOKEN_LENGTH = 12;
const MIN_STANDALONE_TOKEN_LENGTH = 24;
const MAX_TOKEN_LENGTH = 512;

const CONTEXTUAL_ENTROPY_THRESHOLD = 3.2;
const STANDALONE_ENTROPY_THRESHOLD = 4.1;
const MIN_CHAR_CLASSES = 2;

function shouldSkipValue(value: string): boolean {
    const trimmed = value.trim();
    if (trimmed.length > MAX_TOKEN_LENGTH) return true;
    if (trimmed.includes('\n')) return true;
    if (ENTROPY_BLOCKLIST.has(trimmed.toLowerCase())) return true;
    if (ENTROPY_SKIP_PATTERNS.some(pattern => pattern.test(trimmed))) return true;
    if (/^(https?:\/\/|ftp:\/\/|file:\/\/)/i.test(trimmed)) return true;
    if (/^(\/|\.\/|\.\.\/|~\/)/.test(trimmed)) return true;
    if (trimmed.split(/\s+/).length > 3) return true;
    return false;
}

function scoreConfidence(entropy: number, diversity: number, contextual: boolean): number {
    const base = contextual ? 0.64 : 0.56;
    const entropyBoost = contextual
        ? (entropy - CONTEXTUAL_ENTROPY_THRESHOLD) * 0.08
        : (entropy - STANDALONE_ENTROPY_THRESHOLD) * 0.08;
    const diversityBoost = (diversity - 2) * 0.05;
    return Math.min(0.86, Math.max(0.58, base + entropyBoost + diversityBoost));
}

export class EntropyDetector {
    detect(content: string, fileType: string, skipValues: Set<string> = new Set()): SecretDetection[] {
        const results: SecretDetection[] = [];
        const seen = new Set<string>();
        let counter = 0;

        const pushDetection = (value: string, description: string, contextual: boolean): void => {
            const trimmed = value.trim();

            if (trimmed.length > MAX_TOKEN_LENGTH) return;
            if (trimmed.length < (contextual ? MIN_CONTEXTUAL_TOKEN_LENGTH : MIN_STANDALONE_TOKEN_LENGTH)) return;
            if (skipValues.has(trimmed) || seen.has(trimmed) || shouldSkipValue(trimmed)) return;

            const entropy = shannonEntropy(trimmed);
            const diversity = charClassDiversity(trimmed);
            const threshold = contextual ? CONTEXTUAL_ENTROPY_THRESHOLD : STANDALONE_ENTROPY_THRESHOLD;

            if (entropy < threshold || diversity < MIN_CHAR_CLASSES) {
                return;
            }

            seen.add(trimmed);
            counter++;

            const confidence = Math.round(scoreConfidence(entropy, diversity, contextual) * 100) / 100;

            results.push({
                value: trimmed,
                pattern: escapeRegex(trimmed),
                replacement: `HIGH_ENTROPY_${counter}`,
                description: `${description} (${entropy.toFixed(2)} bits, ${diversity} char classes)`,
                confidence,
                source: 'entropy',
                confidenceLevel: toConfidenceLevel(confidence),
            });
        };

        const contextualRegex = /([A-Za-z_][\w.-]{1,64})\s*[:=]\s*["'`]([^"'`\n]{12,512})["'`]/g;
        let m: RegExpExecArray | null;
        while ((m = contextualRegex.exec(content)) !== null) {
            const key = m[1];
            const value = m[2];
            if (!SECRET_FIELD_NAME.test(key)) {
                continue;
            }

            pushDetection(value, `High-entropy value assigned to ${key}`, true);
        }

        const bearerRegex = /(?:Authorization|Bearer)\s*[:=]\s*["']?((?:Bearer\s+)?[A-Za-z0-9._\-+/=]{20,})["']?/gi;
        while ((m = bearerRegex.exec(content)) !== null) {
            const value = m[1].replace(/^Bearer\s+/i, '').trim();
            pushDetection(value, 'High-entropy bearer token', true);
        }

        const tokenRegex = /["'`]([^"'`\n]{24,512})["'`]/g;
        while ((m = tokenRegex.exec(content)) !== null) {
            const value = m[1].trim();
            const likelyInfraFile = ['terraform', 'yaml', 'json', 'dotenv'].includes(fileType);
            if (likelyInfraFile && /[-_]/.test(value) && !/[+/=]/.test(value)) {
                continue;
            }

            pushDetection(value, 'High-entropy string', false);
        }

        return results;
    }
}
