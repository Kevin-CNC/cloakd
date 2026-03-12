export interface PatternMatch {
    pattern: string;  // The regex pattern itself
    match: string;    // The actual matched text
    start: number;
    end: number;
    replacement: string;  // The replacement label
}

interface CompiledPattern {
    pattern: string;
    replacement: string;
    regex: RegExp;
}

function hasUnescapedWildcard(pattern: string): boolean {
    for (let i = 0; i < pattern.length; i++) {
        const char = pattern[i];
        if ((char === '*' || char === '?') && pattern[i - 1] !== '\\') {
            return true;
        }
    }
    return false;
}

function looksLikeRegexPattern(pattern: string): boolean {
    // Keep regex mode for advanced constructs and escaped tokens (\d, \b, etc.).
    return /\\[dDsSwWbBtrnvf]|[\[\](){}+|^$]/.test(pattern);
}

function wildcardToRegexSource(pattern: string): string {
    let source = '';

    for (let i = 0; i < pattern.length; i++) {
        const char = pattern[i];
        const escaped = i > 0 && pattern[i - 1] === '\\';

        if (!escaped && char === '*') {
            source += '[^\\s]*';;
            continue;
        }

        if (!escaped && char === '?') {
            source += '[^\\s]';
            continue;
        }

        if ('\\.^$+{}()|[]'.includes(char)) {
            source += `\\${char}`;
        } else {
            source += char;
        }
    }

    return source;
}

export function toRegexSource(pattern: string): string {
    const trimmedPattern = pattern.trim();

    if (hasUnescapedWildcard(trimmedPattern) && !looksLikeRegexPattern(trimmedPattern)) {
        return wildcardToRegexSource(trimmedPattern);
    }

    return trimmedPattern;
}

export function compilePattern(pattern: string): RegExp {
    return new RegExp(toRegexSource(pattern), 'g');
}

export class RegexPatternMatcher {
    private patterns: CompiledPattern[] = [];

    /**
     * Build the pattern matcher from regex patterns.
     * Invalid patterns are silently dropped with a console warning.
     */
    build(patterns: Array<{ pattern: string; replacement: string }>) {
        const nextPatterns: CompiledPattern[] = [];

        for (const pattern of patterns) {
            try {
                nextPatterns.push({
                    pattern: pattern.pattern,
                    replacement: pattern.replacement,
                    regex: compilePattern(pattern.pattern),
                });
            } catch {
                console.warn(`[PatternMatcher] Invalid regex, skipping: ${pattern.pattern}`);
            }
        }

        this.patterns = nextPatterns;
    }

    /**
     * Find all non-overlapping pattern matches in text.
     *
     * Patterns are tried longest-first so that more specific rules take priority.
     * Occupied character ranges are tracked via sorted intervals (O(n log n))
     * rather than a per-character Set, keeping large texts performant.
     */
    findMatches(text: string): PatternMatch[] {
        const matches: PatternMatch[] = [];
        /** Sorted list of occupied [start, end) intervals. */
        const occupied: Array<[number, number]> = [];

        // Sort patterns by length (longest first) to prioritise longer matches
        const sortedPatterns = [...this.patterns].sort(
            (a, b) => b.pattern.length - a.pattern.length
        );

        for (const { pattern, replacement, regex } of sortedPatterns) {
            try {
                regex.lastIndex = 0;
                let match: RegExpExecArray | null;

                while ((match = regex.exec(text)) !== null) {
                    const start = match.index;
                    const end = match.index + match[0].length;

                    if (!this.overlaps(occupied, start, end)) {
                        matches.push({ pattern, match: match[0], start, end, replacement });
                        this.insertInterval(occupied, start, end);
                    }
                }
            } catch (error) {
                console.error(`[PatternMatcher] Error matching pattern ${pattern}:`, error);
            }
        }

        // Sort by position for consistent ordering
        return matches.sort((a, b) => a.start - b.start);
    }

    // ---- interval helpers -------------------------------------------------------

    /** Binary-search check: does [start, end) overlap any existing interval? */
    private overlaps(intervals: Array<[number, number]>, start: number, end: number): boolean {
        let lo = 0;
        let hi = intervals.length - 1;

        while (lo <= hi) {
            const mid = (lo + hi) >>> 1;
            const [iStart, iEnd] = intervals[mid];

            if (end <= iStart) {
                hi = mid - 1;
            } else if (start >= iEnd) {
                lo = mid + 1;
            } else {
                return true; // overlap
            }
        }
        return false;
    }

    /** Insert [start, end) into the sorted interval list, maintaining order. */
    private insertInterval(intervals: Array<[number, number]>, start: number, end: number): void {
        let lo = 0;
        let hi = intervals.length;

        while (lo < hi) {
            const mid = (lo + hi) >>> 1;
            if (intervals[mid][0] < start) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        intervals.splice(lo, 0, [start, end]);
    }
}