import * as fs from 'fs';
import { SecretDetection } from './ScannerTypes';

// ─────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────

export interface StreamingOptions {
    /** Chunk size in bytes (default 512 KB) */
    chunkSize: number;
    /** Overlap in bytes between consecutive chunks to catch boundary patterns (default 1 KB) */
    overlapSize: number;
}

interface AnalyzeOptions {
    onProgress?: (percent: number) => void;
    cancelled?: { isCancellationRequested: boolean };
}

// ─────────────────────────────────────────────────────────
// Streaming analyzer
// ─────────────────────────────────────────────────────────

export class StreamingAnalyzer {
    private chunkSize: number;
    private overlapSize: number;

    constructor(options: StreamingOptions) {
        this.chunkSize = options.chunkSize;
        this.overlapSize = options.overlapSize;
    }

    /**
     * Read a file in chunks and run the provided scanner function on each chunk.
     * Adjacent chunks overlap by `overlapSize` bytes to avoid missing patterns
     * that straddle chunk boundaries. Deduplication by value across chunks
     * ensures no double-flagging.
     */
    async analyze(
        filePath: string,
        scanChunk: (chunk: string) => SecretDetection[],
        options: AnalyzeOptions = {},
    ): Promise<SecretDetection[]> {
        const { onProgress, cancelled } = options;
        const stat = fs.statSync(filePath);
        const totalSize = stat.size;

        if (totalSize === 0) {
            onProgress?.(100);
            return [];
        }

        const allDetections: SecretDetection[] = [];
        const seenValues = new Set<string>();

        return new Promise<SecretDetection[]>((resolve, reject) => {
            const fd = fs.openSync(filePath, 'r');
            let bytesRead = 0;
            let carryOver = '';

            const readNext = () => {
                if (cancelled?.isCancellationRequested) {
                    fs.closeSync(fd);
                    resolve(this.deduplicateByPattern(allDetections));
                    return;
                }

                const bufSize = Math.min(this.chunkSize, totalSize - bytesRead);
                if (bufSize <= 0) {
                    // Process any remaining carryOver
                    if (carryOver.length > 0) {
                        this.processChunk(carryOver, scanChunk, seenValues, allDetections);
                    }
                    fs.closeSync(fd);
                    onProgress?.(100);
                    resolve(this.deduplicateByPattern(allDetections));
                    return;
                }

                const buf = Buffer.alloc(bufSize);
                const actualRead = fs.readSync(fd, buf, 0, bufSize, bytesRead);
                bytesRead += actualRead;

                // Combine carry-over from previous chunk with new data
                const chunkText = carryOver + buf.toString('utf-8', 0, actualRead);

                // If more data remains, keep the last `overlapSize` chars as carry-over
                if (bytesRead < totalSize) {
                    const splitAt = Math.max(0, chunkText.length - this.overlapSize);
                    const scanPart = chunkText.substring(0, splitAt);
                    carryOver = chunkText.substring(splitAt);
                    this.processChunk(scanPart, scanChunk, seenValues, allDetections);
                } else {
                    // Last chunk — scan everything
                    carryOver = '';
                    this.processChunk(chunkText, scanChunk, seenValues, allDetections);
                }

                const percent = Math.min(95, Math.round((bytesRead / totalSize) * 95));
                onProgress?.(percent);

                // Yield to the event loop so the extension host stays responsive
                setImmediate(readNext);
            };

            try {
                readNext();
            } catch (err) {
                try { fs.closeSync(fd); } catch { /* ignore */ }
                reject(err);
            }
        });
    }

    private processChunk(
        text: string,
        scanChunk: (chunk: string) => SecretDetection[],
        seenValues: Set<string>,
        results: SecretDetection[],
    ): void {
        const chunkResults = scanChunk(text);
        for (const detection of chunkResults) {
            if (!seenValues.has(detection.value)) {
                seenValues.add(detection.value);
                results.push(detection);
            }
        }
    }

    private deduplicateByPattern(detections: SecretDetection[]): SecretDetection[] {
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
