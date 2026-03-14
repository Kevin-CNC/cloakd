export type ToolTrustMode = 'tokenOnly' | 'selectiveDeanonymize' | 'trusted';

export interface ToolWrappingPolicy {
    mode: ToolTrustMode;
    allowedInputPaths: string[];
    allowExternal: boolean;
    maxInputSize: number;
    maxOutputSize: number;
}

export interface ToolWrappingPolicyConfig {
    defaultPolicy?: Partial<ToolWrappingPolicy>;
    perTool?: Record<string, Partial<ToolWrappingPolicy>>;
}

export const DEFAULT_TOOL_POLICY: ToolWrappingPolicy = {
    mode: 'tokenOnly',
    allowedInputPaths: [],
    allowExternal: false,
    maxInputSize: 100_000,
    maxOutputSize: 150_000,
};

function asFinitePositiveInteger(value: unknown, fallback: number): number {
    if (typeof value !== 'number' || !Number.isFinite(value)) {
        return fallback;
    }

    const normalized = Math.floor(value);
    return normalized > 0 ? normalized : fallback;
}

function asStringArray(value: unknown): string[] {
    if (!Array.isArray(value)) {
        return [];
    }

    return value.filter((entry): entry is string => typeof entry === 'string').map(item => item.trim()).filter(Boolean);
}

function normalizePolicy(partialPolicy: Partial<ToolWrappingPolicy> | undefined, fallback: ToolWrappingPolicy): ToolWrappingPolicy {
    const mode = partialPolicy?.mode;
    const normalizedMode: ToolTrustMode =
        mode === 'trusted' || mode === 'selectiveDeanonymize' || mode === 'tokenOnly'
            ? mode
            : fallback.mode;

    return {
        mode: normalizedMode,
        allowedInputPaths: partialPolicy?.allowedInputPaths ? asStringArray(partialPolicy.allowedInputPaths) : fallback.allowedInputPaths,
        allowExternal: typeof partialPolicy?.allowExternal === 'boolean' ? partialPolicy.allowExternal : fallback.allowExternal,
        maxInputSize: asFinitePositiveInteger(partialPolicy?.maxInputSize, fallback.maxInputSize),
        maxOutputSize: asFinitePositiveInteger(partialPolicy?.maxOutputSize, fallback.maxOutputSize),
    };
}

function stringifyInput(input: object): string {
    return JSON.stringify(input);
}

function splitPath(pathSpec: string): string[] {
    return pathSpec
        .split('.')
        .map(segment => segment.trim())
        .filter(Boolean);
}

function pathMatches(pattern: string, targetSegments: string[]): boolean {
    const patternSegments = splitPath(pattern);
    if (patternSegments.length !== targetSegments.length) {
        return false;
    }

    for (let index = 0; index < patternSegments.length; index += 1) {
        if (patternSegments[index] !== '*' && patternSegments[index] !== targetSegments[index]) {
            return false;
        }
    }

    return true;
}

function shouldDeanonymizePath(pathSegments: string[], allowedPaths: readonly string[]): boolean {
    if (allowedPaths.length === 0) {
        return false;
    }

    return allowedPaths.some(pathPattern => pathMatches(pathPattern, pathSegments));
}

type DeanonymizeFn = (text: string) => string;

function transformTrusted(value: unknown, deanonymize: DeanonymizeFn): unknown {
    if (typeof value === 'string') {
        return deanonymize(value);
    }

    if (Array.isArray(value)) {
        return value.map(entry => transformTrusted(entry, deanonymize));
    }

    if (value !== null && typeof value === 'object') {
        const result: Record<string, unknown> = {};
        for (const [key, nestedValue] of Object.entries(value)) {
            result[key] = transformTrusted(nestedValue, deanonymize);
        }
        return result;
    }

    return value;
}

function transformSelective(
    value: unknown,
    deanonymize: DeanonymizeFn,
    allowedPaths: readonly string[],
    pathSegments: string[] = []
): unknown {
    if (typeof value === 'string') {
        return shouldDeanonymizePath(pathSegments, allowedPaths) ? deanonymize(value) : value;
    }

    if (Array.isArray(value)) {
        return value.map((entry, index) => transformSelective(entry, deanonymize, allowedPaths, [...pathSegments, String(index)]));
    }

    if (value !== null && typeof value === 'object') {
        const result: Record<string, unknown> = {};
        for (const [key, nestedValue] of Object.entries(value)) {
            result[key] = transformSelective(nestedValue, deanonymize, allowedPaths, [...pathSegments, key]);
        }
        return result;
    }

    return value;
}

function cloneAsObject(input: object): object {
    const serialized = stringifyInput(input);
    const parsed: unknown = JSON.parse(serialized);
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('Tool input must be a JSON object.');
    }

    return parsed;
}

export class ToolPolicyEngine {
    private readonly defaultPolicy: ToolWrappingPolicy;
    private readonly perTool: Record<string, ToolWrappingPolicy>;

    constructor(config?: ToolWrappingPolicyConfig) {
        this.defaultPolicy = normalizePolicy(config?.defaultPolicy, DEFAULT_TOOL_POLICY);
        const rawPerTool = config?.perTool ?? {};
        const nextPerTool: Record<string, ToolWrappingPolicy> = {};

        for (const [toolName, policy] of Object.entries(rawPerTool)) {
            nextPerTool[toolName] = normalizePolicy(policy, this.defaultPolicy);
        }

        this.perTool = nextPerTool;
    }

    resolvePolicy(toolName: string): ToolWrappingPolicy {
        return this.perTool[toolName] ?? this.defaultPolicy;
    }

    canInvokeExternalTool(toolName: string, policy: ToolWrappingPolicy): boolean {
        if (policy.mode === 'tokenOnly') {
            return true;
        }

        const isCloakdTool = toolName.startsWith('cloakd_');
        return isCloakdTool || policy.allowExternal;
    }

    prepareInputForInvocation(
        input: object,
        policy: ToolWrappingPolicy,
        deanonymize: DeanonymizeFn
    ): object {
        const serializedInput = stringifyInput(input);
        if (Buffer.byteLength(serializedInput, 'utf8') > policy.maxInputSize) {
            throw new Error(`Tool input exceeds maximum allowed size (${policy.maxInputSize} bytes).`);
        }

        if (policy.mode === 'tokenOnly') {
            return cloneAsObject(input);
        }

        const baseInput = cloneAsObject(input);
        if (policy.mode === 'trusted') {
            const transformed = transformTrusted(baseInput, deanonymize);
            if (transformed === null || typeof transformed !== 'object' || Array.isArray(transformed)) {
                throw new Error('Trusted transformation produced non-object tool input.');
            }
            return transformed;
        }

        const transformed = transformSelective(baseInput, deanonymize, policy.allowedInputPaths);
        if (transformed === null || typeof transformed !== 'object' || Array.isArray(transformed)) {
            throw new Error('Selective transformation produced non-object tool input.');
        }

        return transformed;
    }
}
