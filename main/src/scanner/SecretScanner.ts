import * as fs from 'fs';
import * as path from 'path';
import { RegexDetector } from './detectors/RegexDetector';
import { EntropyDetector } from './detectors/EntropyDetector';
import { ScanOptions, SecretDetection, SecretScannedRule } from './ScannerTypes';
import { StreamingAnalyzer } from './StreamingAnalyzer';

const STREAMING_THRESHOLD = 1 * 1024 * 1024;

function generateId(): string {
    return `rule_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

function resolveFileType(filePath: string): string {
    const ext = path.extname(filePath).toLowerCase();
    const map: Record<string, string> = {
        '.py': 'python',
        '.js': 'javascript',
        '.ts': 'typescript',
        '.jsx': 'javascript',
        '.tsx': 'typescript',
        '.go': 'go',
        '.rb': 'ruby',
        '.java': 'java',
        '.cs': 'csharp',
        '.tf': 'terraform',
        '.tfvars': 'terraform',
        '.yml': 'yaml',
        '.yaml': 'yaml',
        '.json': 'json',
        '.env': 'dotenv',
        '.sh': 'shell',
        '.bash': 'shell',
        '.zsh': 'shell',
        '.toml': 'toml',
        '.ini': 'ini',
        '.cfg': 'ini',
        '.conf': 'ini',
        '.properties': 'properties',
        '.xml': 'xml',
        '.dockerfile': 'docker',
    };
    const baseName = path.basename(filePath).toLowerCase();
    if (baseName === 'dockerfile' || baseName.startsWith('dockerfile.')) return 'docker';
    if (baseName === '.env' || baseName.startsWith('.env.')) return 'dotenv';
    return map[ext] ?? 'generic';
}

export class SecretScanner {
    private regexDetector = new RegexDetector();
    private entropyDetector = new EntropyDetector();

    async scanFile(filePath: string, options: ScanOptions = {}): Promise<SecretScannedRule[]> {
        const {
            minConfidence = 0.6,
            enableEntropy = true,
            enableRegex = true,
            onProgress,
            cancelled,
        } = options;

        const fileType = resolveFileType(filePath);
        const stat = fs.statSync(filePath);

        let detections: SecretDetection[];

        if (stat.size > STREAMING_THRESHOLD) {
            detections = await this.scanStreaming(filePath, fileType, {
                enableRegex,
                enableEntropy,
                onProgress,
                cancelled,
            });
        } else {
            onProgress?.(10);
            const content = fs.readFileSync(filePath, 'utf-8');
            onProgress?.(30);
            detections = this.scanContent(content, fileType, enableRegex, enableEntropy);
            onProgress?.(90);
        }

        return this.toScannedRules(detections, minConfidence, onProgress);
    }

    async scanText(content: string, filePath: string, options: ScanOptions = {}): Promise<SecretScannedRule[]> {
        const {
            minConfidence = 0.6,
            enableEntropy = true,
            enableRegex = true,
            onProgress,
        } = options;

        const fileType = resolveFileType(filePath);

        onProgress?.(20);
        const detections = this.scanContent(content, fileType, enableRegex, enableEntropy);
        onProgress?.(90);

        return this.toScannedRules(detections, minConfidence, onProgress);
    }

    private toScannedRules(
        detections: SecretDetection[],
        minConfidence: number,
        onProgress?: (percent: number) => void,
    ): SecretScannedRule[] {
        const filtered = detections.filter(d => d.confidence >= minConfidence);
        const deduped = this.deduplicate(filtered);

        onProgress?.(100);

        return deduped.map(d => ({
            id: generateId(),
            pattern: d.pattern,
            replacement: d.replacement,
            description: `[${d.confidenceLevel.toUpperCase()}] ${d.description}`,
            source: d.source,
            confidence: d.confidence,
            confidenceLevel: d.confidenceLevel,
        }));
    }

    scanContent(
        content: string,
        fileType: string,
        enableRegex: boolean,
        enableEntropy: boolean,
    ): SecretDetection[] {
        const results: SecretDetection[] = [];

        if (enableRegex) {
            results.push(...this.regexDetector.detect(content, fileType));
        }

        if (enableEntropy) {
            const regexValues = new Set(results.map(r => r.value));
            results.push(...this.entropyDetector.detect(content, fileType, regexValues));
        }

        return results;
    }

    private async scanStreaming(
        filePath: string,
        fileType: string,
        opts: Pick<ScanOptions, 'enableRegex' | 'enableEntropy' | 'onProgress' | 'cancelled'>,
    ): Promise<SecretDetection[]> {
        const analyzer = new StreamingAnalyzer({
            chunkSize: 512 * 1024,
            overlapSize: 1024,
        });

        return analyzer.analyze(filePath, (chunk: string) => {
            return this.scanContent(
                chunk,
                fileType,
                opts.enableRegex ?? true,
                opts.enableEntropy ?? true,
            );
        }, {
            onProgress: opts.onProgress,
            cancelled: opts.cancelled,
        });
    }

    private deduplicate(detections: SecretDetection[]): SecretDetection[] {
        const byPattern = new Map<string, SecretDetection>();

        for (const d of detections) {
            const existing = byPattern.get(d.pattern);
            if (!existing || d.confidence > existing.confidence) {
                byPattern.set(d.pattern, d);
            }
        }

        return [...byPattern.values()];
    }
}
