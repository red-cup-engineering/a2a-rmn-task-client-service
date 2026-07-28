export interface RmnA2aExchange {
  readonly result: Record<string, any>;
  readonly inputNi: string;
  readonly outputNi: string;
  readonly agentCard?: Record<string, any>;
  readonly authentication: Readonly<{
    readonly required: boolean;
    readonly agentCardSignatureVerified: boolean;
  }>;
  readonly extensions: readonly string[];
}

export interface RmnA2aSubmission {
  readonly task: Record<string, any>;
  readonly taskId: string;
  readonly inputNi: string;
  readonly agentCard?: Record<string, any>;
  readonly authentication: Readonly<{
    readonly required: boolean;
    readonly agentCardSignatureVerified: boolean;
  }>;
  readonly extensions: readonly string[];
}

export declare class A2aTaskPendingError extends Error {
  readonly task: Record<string, any>;
  readonly taskId?: string;
  readonly agentUrl?: string;
}

export declare function a2aResultParts(result: Record<string, any>): readonly Record<string, any>[];
export declare function a2aResultMetadata(result: Record<string, any>): Readonly<Record<string, any>>;

export declare function submitRmnTask(options: {
  readonly agentUrl: string;
  readonly extensions?: readonly string[];
  readonly message: Record<string, any>;
  readonly requireSignature?: boolean;
  readonly bearerTokenFile?: string;
  readonly outboundTaskRoot?: string;
  readonly callbackUrl?: string;
  readonly callbackToken?: string;
  readonly onTaskObservation?: (task: Record<string, any>) => void | Promise<void>;
  readonly signal?: AbortSignal;
}): Promise<RmnA2aSubmission>;

export declare function sendRmnTask(options: {
  readonly agentUrl: string;
  readonly extensions?: readonly string[];
  readonly message: Record<string, any>;
  readonly requireSignature?: boolean;
  readonly bearerTokenFile?: string;
  readonly outboundTaskRoot?: string;
  readonly callbackUrl?: string;
  readonly callbackToken?: string;
  readonly onTaskObservation?: (task: Record<string, any>) => void | Promise<void>;
  readonly signal?: AbortSignal;
}): Promise<RmnA2aExchange>;

export declare function resumeRmnTask(options: {
  readonly agentUrl: string;
  readonly taskId: string;
  readonly inputNi?: string;
  readonly extensions?: readonly string[];
  readonly requireSignature?: boolean;
  readonly bearerTokenFile?: string;
  readonly onTaskObservation?: (task: Record<string, any>) => void | Promise<void>;
  readonly signal?: AbortSignal;
}): Promise<RmnA2aExchange>;

export declare function cancelRmnTask(options: {
  readonly agentUrl: string;
  readonly taskId: string;
  readonly extensions?: readonly string[];
  readonly requireSignature?: boolean;
  readonly bearerTokenFile?: string;
  readonly onTaskObservation?: (task: Record<string, any>) => void | Promise<void>;
  readonly signal?: AbortSignal;
}): Promise<Omit<RmnA2aSubmission, "inputNi">>;
