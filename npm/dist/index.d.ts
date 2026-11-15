export type StreamSubscriber = (bytes: Uint8Array, isText: boolean) => void;

export interface AxilClientOptions {
  url?: string;
  autoConnect?: boolean;
}

export interface AxilNativeBinding {
  cli(args: string[]): number;
  statusText(code: number): string;
  urlEncode(input: string): string;
  urlDecode(input: string): string;
  jsonEscape(input: string): string;
  slugify(input: string): string;
}

export declare function getNativeAxil(): AxilNativeBinding | null;
export declare function resolveModulePath(modSpec: string, callerImportMetaUrl?: string): string;
export declare function normalizeCliArgs(args?: string[], callerImportMetaUrl?: string): string[];
export declare function runCli(args?: string[]): number;
export declare function statusText(code: number): string;
export declare function urlEncode(input: string): string;
export declare function urlDecode(input: string): string;
export declare function jsonEscape(input: string): string;
export declare function slugify(input: string): string;

export declare class AxilClient {
  url: string | null;
  status: number;
  constructor(options?: AxilClientOptions);
  connect(url?: string): void;
  send(data: string | Uint8Array | ArrayBuffer): boolean;
  sendChannel(channel: number, data: string | Uint8Array | ArrayBuffer): boolean;
  subscribe(cb: StreamSubscriber): () => boolean;
  subscribeChannel(channel: number, cb: StreamSubscriber): () => boolean;
  close(): void;
}

export { createAxilBridge, AxilBridge } from "./bridge.js";
