import * as vscode from 'vscode';

/**
 * Minimal anonymizer contract used by the language model wrapper.
 */
export interface Anonymizer {
    anonymize(text: string): string | Promise<string>;
    deanonymize(text: string): string;
}

function assertNever(value: never, message: string): never {
    throw new Error(message + ': ' + String(value));
}

async function anonymizeText(anonymizer: Anonymizer, text: string): Promise<string> {
    return await anonymizer.anonymize(text);
}

function cloneToolCallInput(input: object): object {
    const serialized = JSON.stringify(input);
    const parsed: unknown = JSON.parse(serialized);
    if (parsed === null || typeof parsed !== 'object') {
        throw new Error('Tool call input must serialize to an object.');
    }
    return parsed;
}

/**
 * Anonymize a single content part for outbound model requests.
 */
export async function anonymizeContentPart(
    part: vscode.LanguageModelInputPart,
    anonymizer: Anonymizer
): Promise<vscode.LanguageModelInputPart> {
    if (part instanceof vscode.LanguageModelTextPart) {
        const anonymizedValue = await anonymizeText(anonymizer, part.value);
        return new vscode.LanguageModelTextPart(anonymizedValue);
    }

    if (part instanceof vscode.LanguageModelToolCallPart) {
        const serializedInput = JSON.stringify(part.input);
        const anonymizedSerializedInput = await anonymizeText(anonymizer, serializedInput);
        const parsedInput: unknown = JSON.parse(anonymizedSerializedInput);
        if (parsedInput === null || typeof parsedInput !== 'object') {
            throw new Error('Anonymized tool call input must deserialize to an object.');
        }

        return new vscode.LanguageModelToolCallPart(
            part.callId,
            part.name,
            cloneToolCallInput(parsedInput)
        );
    }

    if (part instanceof vscode.LanguageModelToolResultPart) {
        const anonymizedContent: Array<vscode.LanguageModelTextPart | vscode.LanguageModelPromptTsxPart | vscode.LanguageModelDataPart | unknown> = [];

        for (const contentPart of part.content) {
            if (contentPart instanceof vscode.LanguageModelTextPart) {
                const anonymizedValue = await anonymizeText(anonymizer, contentPart.value);
                anonymizedContent.push(new vscode.LanguageModelTextPart(anonymizedValue));
                continue;
            }

            if (typeof contentPart === 'string') {
                anonymizedContent.push(await anonymizeText(anonymizer, contentPart));
                continue;
            }

            anonymizedContent.push(contentPart);
        }

        return new vscode.LanguageModelToolResultPart(part.callId, anonymizedContent);
    }

    if (part instanceof vscode.LanguageModelDataPart) {
        return part;
    }

    return assertNever(part, 'Unhandled message content part');
}

/**
 * Create anonymized copies of messages while preserving order and metadata.
 */
export async function anonymizeMessages(
    messages: readonly vscode.LanguageModelChatMessage[],
    anonymizer: Anonymizer
): Promise<vscode.LanguageModelChatMessage[]> {
    const transformed: vscode.LanguageModelChatMessage[] = [];

    for (const message of messages) {
        const anonymizedParts: vscode.LanguageModelInputPart[] = [];
        for (const part of message.content) {
            anonymizedParts.push(await anonymizeContentPart(part, anonymizer));
        }

        switch (message.role) {
            case vscode.LanguageModelChatMessageRole.User:
            case vscode.LanguageModelChatMessageRole.Assistant:
                transformed.push(new vscode.LanguageModelChatMessage(message.role, anonymizedParts, message.name));
                break;
            default:
                assertNever(message.role, 'Unhandled chat message role');
        }
    }

    return transformed;
}

/**
 * Lazily wraps a model response stream and deanonymizes text chunks in-flight.
 */
export function wrapResponseStream(
    stream: AsyncIterable<vscode.LanguageModelTextPart | vscode.LanguageModelToolCallPart | vscode.LanguageModelDataPart | unknown>,
    anonymizer: Anonymizer
): AsyncIterable<vscode.LanguageModelTextPart | vscode.LanguageModelToolCallPart | vscode.LanguageModelDataPart | unknown> {
    async function* transform(): AsyncIterable<vscode.LanguageModelTextPart | vscode.LanguageModelToolCallPart | vscode.LanguageModelDataPart | unknown> {
        for await (const chunk of stream) {
            if (chunk instanceof vscode.LanguageModelTextPart) {
                yield new vscode.LanguageModelTextPart(anonymizer.deanonymize(chunk.value));
                continue;
            }

            yield chunk;
        }
    }

    return transform();
}

/**
 * Create a drop-in LanguageModelChat wrapper that enforces Cloakd anonymization boundaries.
 */
export function createAnonymizedModel(
    model: vscode.LanguageModelChat,
    anonymizer: Anonymizer
): vscode.LanguageModelChat {
    const handler: ProxyHandler<vscode.LanguageModelChat> = {
        get(target, property, receiver): unknown {
            if (property === 'sendRequest') {
                return async (
                    messages: vscode.LanguageModelChatMessage[],
                    options?: vscode.LanguageModelChatRequestOptions,
                    token?: vscode.CancellationToken
                ): Promise<vscode.LanguageModelChatResponse> => {
                    const anonymizedMessages = await anonymizeMessages(messages, anonymizer);
                    const response = await target.sendRequest(anonymizedMessages, options, token);

                    return {
                        stream: wrapResponseStream(response.stream, anonymizer),
                        text: (async function* (): AsyncIterable<string> {
                            for await (const textChunk of response.text) {
                                yield anonymizer.deanonymize(textChunk);
                            }
                        })(),
                    };
                };
            }

            const value = Reflect.get(target, property, receiver);
            if (typeof value === 'function') {
                return value.bind(target);
            }

            return value;
        },
    };

    return new Proxy(model, handler);
}