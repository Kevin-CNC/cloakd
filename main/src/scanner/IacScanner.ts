import * as fs from 'fs';
import * as path from 'path';

export interface ScannedRule {
    id: string;
    pattern: string;
    replacement: string;
    description: string;
    source: string;
    confidence?: number;
    confidenceLevel?: 'high' | 'medium' | 'low';
}

// ─────────────────────────────────────────────────────────
// Terraform-aware pattern detectors
// ─────────────────────────────────────────────────────────

interface DetectorResult {
    /** The literal value that was found */
    value: string;
    /** A regex pattern string that will match this value */
    pattern: string;
    /** A descriptive token name for the replacement */
    replacement: string;
    /** Short human-readable description */
    description: string;
}

/**
 * Escapes a string so it can be used literally inside a RegExp.
 */
function escapeRegex(s: string): string {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function generateId(): string {
    return `rule_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

const CIDR_ALLOWLIST = new Set([
    '0.0.0.0/0',
    '::/0',
]);

// Well-known generic placeholder usernames that are NOT real credentials.
// These are framework defaults / documentation examples — flagging them
// creates noise and violates the "avoids the admin false-positive" design contract.
const DB_USER_BLOCKLIST = new Set([
    'admin', 'root', 'postgres', 'mysql', 'oracle',
    'sa', 'user', 'dbuser', 'dbadmin', 'administrator',
]);

// Well-known public AWS account IDs (published in official vendor documentation).
// These are not sensitive — flagging them creates noise for users.
const PUBLIC_AWS_ACCOUNT_BLOCKLIST = new Set([
    '099720109477', // Canonical (Ubuntu)
    '137112412989', // Amazon Linux (Amazon)
    '309956199498', // Red Hat
    '125523088429', // CentOS
    '013907871322', // Kali Linux
    '679593333241', // openSUSE
]);

const GENERIC_NAME_TOKENS = new Set([
    'web', 'app', 'db', 'api', 'lb', 'sg', 'rt', 'igw', 'nat', 'vpc',
    'public', 'private', 'internal', 'external', 'server', 'worker',
    'frontend', 'backend', 'proxy', 'cache', 'queue', 'bus', 'data',
    'subnet', 'group', 'cluster', 'node', 'pod', 'svc', 'service',
    'gateway', 'listener', 'target', 'route', 'table', 'association',
    'instance', 'launch', 'template', 'asg', 'tg', 'alb', 'nlb', 'elb',
    // HCL attribute key literals that can appear as values in filter blocks
    'name', 'key', 'tag', 'id', 'env',
]);

// HCL field values that are protocol / engine type literals — never
// infrastructure identifiers regardless of context.
const RESOURCE_NAME_VALUE_BLOCKLIST = new Set([
    'HTTP', 'HTTPS', 'TCP', 'UDP', 'application', 'network',
    'gateway', 'instance', 'postgres', 'mysql', 'aurora', 'mariadb',
]);

function isGenericName(name: string): boolean {
    const tokens = name.toLowerCase().split(/[-_\s]+/).filter(Boolean);
    return tokens.length > 0 && tokens.every(t => GENERIC_NAME_TOKENS.has(t));
}

// ── Individual detectors ─────────────────────────────────

function detectCidrBlocks(content: string): DetectorResult[] {
    const results: DetectorResult[] = [];
    const seen = new Set<string>();
    const regex = /\b(\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2})\b/g;
    let m: RegExpExecArray | null;
    let counter = 1;
    while ((m = regex.exec(content)) !== null) {
        const cidr = m[1];
        // Skip routing-convention catch-all CIDRs — they are not secrets
        if (CIDR_ALLOWLIST.has(cidr)) { continue; }
        if (seen.has(cidr)) { continue; }
        seen.add(cidr);
        results.push({
            value: cidr,
            pattern: escapeRegex(cidr),
            replacement: `CIDR_BLOCK_${counter}`,
            description: `CIDR block: ${cidr}`,
        });
        counter++;
    }
    return results;
}

function detectAwsAccountIds(content: string): DetectorResult[] {
    const results: DetectorResult[] = [];
    const seen = new Set<string>();
    // Require surrounding quotes to avoid matching storage sizes, port ranges,
    // version numbers, etc. that happen to be 12 digits.
    const regex = /["'](\d{12})["']/g;
    let m: RegExpExecArray | null;
    let counter = 1;
    while ((m = regex.exec(content)) !== null) {
        const id = m[1];
        // Skip well-known public vendor account IDs — they are documented openly
        // and carry no confidentiality risk.
        if (PUBLIC_AWS_ACCOUNT_BLOCKLIST.has(id)) { continue; }
        if (seen.has(id)) { continue; }
        seen.add(id);
        results.push({
            value: id,
            pattern: escapeRegex(id),
            replacement: `AWS_ACCOUNT_${counter}`,
            description: `AWS account / owner ID: ${id}`,
        });
        counter++;
    }
    return results;
}

function detectFilePaths(content: string): DetectorResult[] {
    const results: DetectorResult[] = [];
    const seen = new Set<string>();
    // Match sensitive key/cert file paths whether via file("...") or a bare string
    const regex = /(?:file\(["']|["'])((?:~\/|\/)[^\s"')]+\.(?:pub|pem|key|crt|cer|pfx|p12|jks))\b/g;
    let m: RegExpExecArray | null;
    let counter = 1;
    while ((m = regex.exec(content)) !== null) {
        const fp = m[1];
        if (seen.has(fp)) { continue; }
        seen.add(fp);
        results.push({
            value: fp,
            pattern: escapeRegex(fp),
            replacement: `FILE_PATH_${counter}`,
            description: `Sensitive file path: ${fp}`,
        });
        counter++;
    }
    return results;
}

function detectDbCredentials(content: string): DetectorResult[] {
    const results: DetectorResult[] = [];
    const seen = new Set<string>();

    // username = "literal" only.
    // Variable refs (var.x), resource refs (random_password.x.result), and
    // data source refs do NOT use surrounding quotes in HCL — they are bare
    // expressions. Requiring quotes here prevents false positives like "admin"
    // appearing in unrelated contexts (HTML, comments, nav items, etc.).
    const usernameRegex = /\busername\s*=\s*["']([^"'\s${]+)["']/gi;
    let m: RegExpExecArray | null;
    let userCounter = 1;
    while ((m = usernameRegex.exec(content)) !== null) {
        const val = m[1];
        // Skip well-known generic placeholder usernames — these are framework
        // defaults and documentation examples, not real credentials.
        if (DB_USER_BLOCKLIST.has(val.toLowerCase())) { continue; }
        if (seen.has(val)) { continue; }
        seen.add(val);
        results.push({
            value: val,
            pattern: escapeRegex(val),
            replacement: `DB_USER_${userCounter}`,
            description: `Hardcoded DB username: ${val}`,
        });
        userCounter++;
    }

    // password = "literal" only — variable refs (e.g. random_password.db.result)
    // are bare HCL expressions and will never be quoted.
    const passwordRegex = /\bpassword\s*=\s*["']([^"'\s${]{4,})["']/gi;
    let passCounter = 1;
    while ((m = passwordRegex.exec(content)) !== null) {
        const val = m[1];
        if (seen.has(val)) { continue; }
        seen.add(val);
        results.push({
            value: val,
            pattern: escapeRegex(val),
            replacement: `DB_PASSWORD_${passCounter}`,
            description: `Hardcoded DB password: ${val}`,
        });
        passCounter++;
    }

    return results;
}

function detectResourceNames(content: string): DetectorResult[] {
    const results: DetectorResult[] = [];
    const seen = new Set<string>();
    // Match Name tags and key identifier fields. Bucket fields are intentionally
    // excluded here — they are handled by detectBucketNames() which runs first,
    // and the shared `seenPatterns` set in deduplicateAndConvert() prevents
    // double-capture.
    const regex = /(?:^|\s)(?:Name|name|identifier|key_name)\s*=\s*["']([^"'${}\s]+)["']/gm;
    let m: RegExpExecArray | null;
    let counter = 1;
    while ((m = regex.exec(content)) !== null) {
        const name = m[1];        // Skip values shorter than 5 characters — single-word HCL keywords
        // (e.g. "name", "key", "id") or trivial labels that are never identifiers.
        if (name.length < 5) { continue; }        // Skip HCL protocol / engine type literals
        if (RESOURCE_NAME_VALUE_BLOCKLIST.has(name)) { continue; }
        // Skip interpolation expressions (contain ${)
        if (name.includes('${')) { continue; }
        // Skip purely generic role-descriptive labels
        if (isGenericName(name)) { continue; }
        if (seen.has(name)) { continue; }
        seen.add(name);
        results.push({
            value: name,
            pattern: escapeRegex(name),
            replacement: `RESOURCE_NAME_${counter}`,
            description: `Infrastructure resource name: ${name}`,
        });
        counter++;
    }
    return results;
}

function detectRegions(content: string): DetectorResult[] {
    const results: DetectorResult[] = [];
    const seen = new Set<string>();
    // AWS / GCP / Azure region identifiers — must be quoted to avoid matching
    // prose or variable names that happen to contain directional words.
    const regex = /["']((?:us|eu|ap|sa|ca|me|af|il)-(?:east|west|north|south|central|northeast|southeast|southwest|northwest)-\d)["']/g;
    let m: RegExpExecArray | null;
    let counter = 1;
    while ((m = regex.exec(content)) !== null) {
        const region = m[1];
        if (seen.has(region)) { continue; }
        seen.add(region);
        results.push({
            value: region,
            pattern: escapeRegex(region),
            replacement: `REGION_${counter}`,
            description: `Cloud region: ${region}`,
        });
        counter++;
    }
    return results;
}

function detectApiKeysAndSecrets(content: string): DetectorResult[] {
    const results: DetectorResult[] = [];
    const seen = new Set<string>();
    // Only flag values ≥ 16 chars to avoid short config strings. Bare HCL
    // expressions (var.x, data.x) are never quoted so they are naturally excluded.
    const regex = /(?:api_key|secret_key|access_key|auth_token|client_secret|webhook_secret)\s*=\s*["']([^"'\s${]{16,})["']/gi;
    let m: RegExpExecArray | null;
    let counter = 1;
    while ((m = regex.exec(content)) !== null) {
        const secret = m[1];
        if (seen.has(secret)) { continue; }
        seen.add(secret);
        results.push({
            value: secret,
            pattern: escapeRegex(secret),
            replacement: `SECRET_${counter}`,
            description: `Inline secret / API key`,
        });
        counter++;
    }
    return results;
}

function detectBucketNames(content: string): DetectorResult[] {
    const results: DetectorResult[] = [];
    const seen = new Set<string>();
    // bucket = "literal-name" — skip interpolated values (contain ${)
    const regex = /\bbucket\s*=\s*["']([^"'${}\s]+)["']/g;
    let m: RegExpExecArray | null;
    let counter = 1;
    while ((m = regex.exec(content)) !== null) {
        const bucket = m[1];
        if (seen.has(bucket)) { continue; }
        seen.add(bucket);
        results.push({
            value: bucket,
            pattern: escapeRegex(bucket),
            replacement: `BUCKET_NAME_${counter}`,
            description: `Storage bucket name: ${bucket}`,
        });
        counter++;
    }
    return results;
}

function detectAmiIds(content: string): DetectorResult[] {
    const results: DetectorResult[] = [];
    const seen = new Set<string>();
    // Explicit AMI IDs: ami-xxxxxxxx (8 hex) or ami-xxxxxxxxxxxxxxxxx (17 hex)
    const regex = /\b(ami-[0-9a-f]{8,17})\b/g;
    let m: RegExpExecArray | null;
    let counter = 1;
    while ((m = regex.exec(content)) !== null) {
        const ami = m[1];
        if (seen.has(ami)) { continue; }
        seen.add(ami);
        results.push({
            value: ami,
            pattern: escapeRegex(ami),
            replacement: `AMI_ID_${counter}`,
            description: `AMI identifier: ${ami}`,
        });
        counter++;
    }
    return results;
}

function detectAmiFilterPatterns(content: string): DetectorResult[] {
    const results: DetectorResult[] = [];
    const seen = new Set<string>();
    // AMI name filter strings used in data "aws_ami" filter blocks.
    // These are OS/distro fingerprints (e.g. "ubuntu/images/hvm-ssd/...") that
    // uniquely identify the infrastructure baseline and should be anonymized.
    // Must contain a forward slash (path-like) and an architecture/storage keyword.
    const regex = /["']([a-z][a-z0-9_\-/.*]+(?:server|hvm|ssd|ebs|gp2|arm64|amd64)[a-z0-9_\-/.*]*)["']/gi;
    let m: RegExpExecArray | null;
    let counter = 1;
    while ((m = regex.exec(content)) !== null) {
        const val = m[1];
        if (!val.includes('/')) { continue; }
        if (seen.has(val)) { continue; }
        seen.add(val);
        results.push({
            value: val,
            pattern: escapeRegex(val),
            replacement: `AMI_FILTER_${counter}`,
            description: `AMI name filter pattern: ${val}`,
        });
        counter++;
    }
    return results;
}

function detectArnPatterns(content: string): DetectorResult[] {
    const results: DetectorResult[] = [];
    const seen = new Set<string>();
    // Full AWS ARNs: arn:aws[suffix]:service:region:account:resource
    const regex = /\b(arn:aws[a-zA-Z-]*:[a-zA-Z0-9-]+:[a-z0-9-]*:\d{12}:[^\s"',]+)/g;
    let m: RegExpExecArray | null;
    let counter = 1;
    while ((m = regex.exec(content)) !== null) {
        const arn = m[1];
        if (seen.has(arn)) { continue; }
        seen.add(arn);
        results.push({
            value: arn,
            pattern: escapeRegex(arn),
            replacement: `ARN_${counter}`,
            description: `AWS ARN: ${arn}`,
        });
        counter++;
    }
    return results;
}

function detectPrivateIps(content: string): DetectorResult[] {
    const results: DetectorResult[] = [];
    const seen = new Set<string>();
    // Standalone IPs that are not part of a CIDR block.
    // Negative lookahead (?!\/\d) prevents matching the host portion of a CIDR.
    const regex = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b(?!\/\d)/g;
    let m: RegExpExecArray | null;
    let counter = 1;
    while ((m = regex.exec(content)) !== null) {
        const ip = m[1];
        // Skip well-known non-specific addresses
        if (ip === '0.0.0.0' || ip === '255.255.255.255' || ip.startsWith('127.') || ip.startsWith('169.254.')) {
            continue;
        }
        if (seen.has(ip)) { continue; }
        seen.add(ip);
        results.push({
            value: ip,
            pattern: escapeRegex(ip),
            replacement: `IP_${counter}`,
            description: `IP address: ${ip}`,
        });
        counter++;
    }
    return results;
}

// ── Main scanner class ───────────────────────────────────

export class IacScanner {
    /**
     * Scans the given file and returns candidate anonymization rules.
     * Currently supports Terraform (.tf / .tfvars) and a generic text fallback.
     */
    static async scanFile(filePath: string): Promise<ScannedRule[]> {
        const ext = path.extname(filePath).toLowerCase();
        const content = fs.readFileSync(filePath, 'utf-8');

        switch (ext) {
            case '.tf':
            case '.tfvars':
                return IacScanner.scanTerraform(content);
            default:
                return IacScanner.scanGeneric(content);
        }
    }

    /**
     * Terraform-specific pipeline.
     * Detector order matters: detectors that produce more-specific patterns
     * (buckets, AMI filters) run before broader ones (resource names) so that
     * the global deduplication set prevents the same literal from being captured
     * twice under a less-specific category.
     */
    private static scanTerraform(content: string): ScannedRule[] {
        const allDetections: DetectorResult[] = [
            ...detectCidrBlocks(content),
            ...detectRegions(content),
            ...detectAwsAccountIds(content),
            ...detectArnPatterns(content),
            ...detectAmiIds(content),
            ...detectAmiFilterPatterns(content),
            ...detectFilePaths(content),
            ...detectDbCredentials(content),
            ...detectApiKeysAndSecrets(content),
            ...detectBucketNames(content),      // must precede detectResourceNames
            ...detectResourceNames(content),
            ...detectPrivateIps(content),
        ];

        return IacScanner.deduplicateAndConvert(allDetections, 'terraform');
    }

    /**
     * Generic fallback for non-Terraform IaC files.
     * Runs only format-agnostic detectors.
     */
    private static scanGeneric(content: string): ScannedRule[] {
        const allDetections: DetectorResult[] = [
            ...detectCidrBlocks(content),
            ...detectPrivateIps(content),
            ...detectFilePaths(content),
            ...detectDbCredentials(content),
            ...detectApiKeysAndSecrets(content),
            ...detectAwsAccountIds(content),
            ...detectArnPatterns(content),
            ...detectAmiIds(content),
        ];

        return IacScanner.deduplicateAndConvert(allDetections, 'generic');
    }

    /**
     * Cross-detector deduplication: if two detectors independently find the
     * same regex pattern string, only the first (higher-priority) result is kept.
     * Converts `DetectorResult[]` → `ScannedRule[]`.
     */
    private static deduplicateAndConvert(detections: DetectorResult[], source: string): ScannedRule[] {
        const seenPatterns = new Set<string>();
        const rules: ScannedRule[] = [];

        for (const d of detections) {
            if (seenPatterns.has(d.pattern)) { continue; }
            seenPatterns.add(d.pattern);
            rules.push({
                id: generateId(),
                pattern: d.pattern,
                replacement: d.replacement,
                description: d.description,
                source,
            });
        }

        return rules;
    }
}
