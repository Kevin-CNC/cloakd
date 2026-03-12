export type ConfidenceLevel = 'high' | 'medium' | 'low';

export interface SecretDetection {
    value: string;
    pattern: string;
    replacement: string;
    description: string;
    confidence: number;
    source: 'regex' | 'entropy';
    confidenceLevel: ConfidenceLevel;
}

export interface ScanOptions {
    minConfidence?: number;
    enableEntropy?: boolean;
    enableRegex?: boolean;
    onProgress?: (percent: number) => void;
    cancelled?: { isCancellationRequested: boolean };
}

export interface SecretScannedRule {
    id: string;
    pattern: string;
    replacement: string;
    description: string;
    source: string;
    confidence?: number;
    confidenceLevel?: ConfidenceLevel;
}