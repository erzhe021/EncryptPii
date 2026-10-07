export type TransportMode = 'plain' | 'bidirectional' | 'request-only' | 'response-only'
  | 'response-only/client-exception' | 'response-only/system-exception'
  | 'response-only/business-exception';
export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

export interface TransportRequest {
  url: string;
  method: 'GET' | 'POST';
  data?: JsonValue;
  timeoutMs: number;
  headers: Record<string, string>;
}

export interface TransportResponse {
  statusCode: number;
  data: unknown;
}

export interface ClientOptions {
  baseUrl: string;
  timeoutMs?: number;
  headers?: Record<string, string>;
  transport: (request: TransportRequest) => Promise<TransportResponse>;
  randomBytes: (length: number) => Promise<Uint8Array>;
}

export interface SendOptions {
  mode: TransportMode;
  data: JsonValue;
  headers?: Record<string, string>;
}

export interface Result<T> {
  code: string;
  message: string | null;
  data: T | null;
}

export interface CipherRequest {
  ivBase64: string;
  encryptedDataBase64: string;
}

export interface CipherResponse {
  ivBase64: string;
  encryptedDataBase64: string;
}

export interface DetailedResult<T> {
  data: T;
  cipherRequest: CipherRequest | null;
  cipherResponse: CipherResponse | null;
  stcHeaders: { 'X-STC-KEY-ID': string; 'X-STC-SESSION-KEY': string } | null;
  timings: { total: number; encryption: number; http: number; decryption: number };
}

export interface Client {
  send<T = unknown>(options: SendOptions): Promise<Result<T>>;
  /** Opt-in diagnostics for demos; contains ciphertext but never the session key. */
  sendDetailed<T = unknown>(options: SendOptions): Promise<DetailedResult<Result<T>>>;
}

export type ErrorCode =
  | 'INVALID_ARGUMENT' | 'HTTP_ERROR' | 'NETWORK_ERROR' | 'RANDOM_UNAVAILABLE'
  | 'INVALID_SERVER_KEY' | 'ENCRYPTION_FAILED' | 'INVALID_CIPHER_PAYLOAD'
  | 'DECRYPTION_FAILED' | 'INVALID_RESPONSE' | 'KEY_RETRY_FAILED';

export class SdkError extends Error {
  constructor(code: ErrorCode, message: string, cause?: unknown);
  code: ErrorCode;
  cause?: unknown;
  /** Opt-in diagnostics from sendDetailed, including failed HTTP responses. */
  details?: DetailedResult<unknown>;
}

export class HttpError extends SdkError {
  constructor(statusCode: number, data: unknown);
  statusCode: number;
  /** May contain sensitive server data; do not log by default. */
  data: unknown;
}

export interface WechatPlatform {
  request(options: {
    url: string;
    method: 'GET' | 'POST';
    data?: JsonValue;
    timeout: number;
    header: Record<string, string>;
    success: (response: TransportResponse) => void;
    fail: (error: unknown) => void;
  }): unknown;
  getRandomValues?(options: {
    length: number;
    success: (response: { randomValues: ArrayBuffer | ArrayBufferView }) => void;
    fail: (error: unknown) => void;
  }): unknown;
}

export interface WechatClientOptions {
  baseUrl: string;
  timeoutMs?: number;
  headers?: Record<string, string>;
  platform?: WechatPlatform;
}

export function createClient(options: ClientOptions): Client;
export function createWechatAdapter(platform: WechatPlatform): Pick<ClientOptions, 'transport' | 'randomBytes'>;
export function createWechatClient(options: WechatClientOptions): Client;
